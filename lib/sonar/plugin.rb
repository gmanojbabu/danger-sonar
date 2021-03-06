require 'find'
require 'json'
require 'shellwords'
require 'git_diff_parser'

module Danger

  # Analyse Sonar JSON report.
  # JSON report is generated using [SonarQube Scanner](https://docs.sonarqube.org/display/SCAN/Analyzing+with+SonarQube+Scanner) tool.
  # Results are passed out as a table in markdown.
  #
  # @example Specifying Sonar JSON report file.
  #
  #          # Runs a linter with comma style disabled
  #          sonar.json_report_file = 'sonar_report.json'
  #          sonar.lint_files
  #
  # @see  gmanojbabu
  # @tags swift, sonar, danger
  #
  class DangerSonar < Plugin

    # The path to Sonar report JSON file
    attr_accessor :json_report_file

    # The path to Sonar configuration file
    attr_accessor :config_file

    # By default this plugin compairs each line in modifiled file against sonar issue line no, to turn off set this property to true, to check for file match
    attr_accessor :ignore_file_line_change_check

    attr_accessor :failure_message

    attr_accessor :warning_message

    # Total Sonar blocker issues found in PR changes
    attr_accessor :blocker_count

    # Total Sonar critical issues found in PR changes
    attr_accessor :critical_count

    # Total Sonar major issues found in PR changes
    attr_accessor :major_count

    # Total Sonar minor issues found in PR changes
    attr_accessor :minor_count

    # Total Sonar info issues found in PR changes
    attr_accessor :info_count

     # To log additional information for debuging.
     attr_accessor :verbose

    # Lints Swift files.
    # Generates a `markdown` list of issues(Blocker, Major, Minor, Info) for the prose in a corpus of .markdown and .md files.
    #
    # @param   [String] files
    #          A globbed string which should return the files that you want to lint, defaults to nil.
    #          if nil, modified and added files from the diff will be used.
    # @return  [void]
    #
    def lint_files(files=nil, inline_mode: false)
      # Fails if invalid JSON report file isn't installed
      raise "Sonar report file name is empty" unless !json_report_file.empty?

      # Extract excluded paths
      excluded_paths = excluded_files_from_config(config_file)
      log "Sonar - Excluded paths #{excluded_paths}"

      # Extract swift files (ignoring excluded ones)
      files = find_files(files, excluded_paths)
      log "Sonar - Included files #{files}"


        #file = File.read(json_report_file)
        #sonar_report_data = JSON.parse(file)

      # Prepare options
      options = {
        report: File.expand_path(json_report_file),
        config: config_file
      }

      log "Sonar - options #{options}"

      # Lint each file and collect the results
      issues = analyse_sonar_report(files, options)
      puts "Issues: #{issues}"

      # Filter warnings and errors
      blockers = issues.select { |issue| issue['severity'] == 'BLOCKER' }
      citicals = issues.select { |issue| issue['severity'] == 'CRITICAL' }
      majors = issues.select { |issue| issue['severity'] == 'MAJOR' }
      minors = issues.select { |issue| issue['severity'] == 'MINOR' }
      infos = issues.select { |issue| issue['severity'] == 'INFO' }
      
      @blocker_count = if blockers.nil? then 0 else blockers.length end
      @critical_count = if citicals.nil? then 0 else citicals.length end
      @major_count = if majors.nil? then 0 else majors.length end
      @minor_count = if minors.nil? then 0 else minors.length end
      @info_count = if infos.nil? then 0 else infos.length end

      if inline_mode
        # Reprt with inline comment
        send_inline_comment(blockers, "fail") unless blockers.empty?
        send_inline_comment(citicals, "fail") unless citicals.empty?
        send_inline_comment(majors, "fail") unless majors.empty?
        send_inline_comment(minors, "warn") unless minors.empty?
        send_inline_comment(infos, "warn") unless infos.empty?
      else
        # Report if any blockers or citicals or majors or minors or infos
        if blockers.count > 0 || citicals.count > 0 || majors.count > 0 || minors.count > 0 || infos.count > 0
          message = "### Sonar found issues top 50 in Blocker, Citical, Major, Minor and Info\n\n"
          message << markdown_issues(blockers[0,49], 'Blocker') unless blockers.empty?
          message << markdown_issues(citicals[0,49], 'Critical') unless citicals.empty?
          message << markdown_issues(majors[0,49], 'Major') unless majors.empty?
          message << markdown_issues(minors[0,49], 'Minor') unless minors.empty?
          message << markdown_issues(infos[0,49], 'Info') unless infos.empty?
          puts message
          markdown message
        end
      end

      if failure_message && (blockers.count > 0 || citicals.count > 0 || majors.count > 0)
        fail(failure_message, sticky: false)
      else
          if warning_message && (minors.count > 0 || infos.count > 0)
            fail(failure_message, sticky: false)
          end
      end
    end

    # Analyses Sonar Report and finds files that has sonar issues
    #
    # @return [Array] sonar issues
    def analyse_sonar_report(files, options)
      issues = parse_sonar_report(options[:report])
      # Filter issues that are part of modified files
      issues = issues_in_files_patch(issues)
    end

    def issues_in_files_patch(issues)
      log "Sonar - issues to analyse - \n #{issues}"
      files_patch_info = get_files_patch_info()
      if ignore_file_line_change_check
          return issues.select { |i| files_patch_info.keys.detect{ |k| k.to_s =~ /#{i['file']}/ } }
      else
         return issues.select do |i|
             key = files_patch_info.keys.detect{ |k| k.include?(i['file']) }
             key != nil && (files_patch_info["#{key}"] != nil && (i['line'].to_s.empty? || files_patch_info["#{key}"].include?(i['line'].to_i)))
         end
      end
    end

    def get_files_patch_info()
        modified_files_info = Hash.new
        updated_files = (git.modified_files - git.deleted_files) + git.added_files
        updated_files.each {|file|
            file_info = git.diff_for_file(file)
            file_patches = GitDiffParser.parse(file_info.patch)
            file_patches.each do |patch|
                if modified_files_info["#{File.expand_path(file)}"] == nil
                    modified_files_info[File.expand_path(file)] = Array(patch.changed_line_numbers)
                else
                    modified_files_info[File.expand_path(file)].push(patch.changed_line_numbers)
                end
            end
        }
        modified_files_info
    end



    def parse_sonar_report(report_file)
        file = File.read(report_file)
        sonar_report_data = JSON.parse(file)
        issues = Array.new
        sonar_report_data["issues"].each {|i|
                issue = {}
                issue["file"] = i["component"].to_s.split(":").last
                issue["line"] = i["line"].to_s
                issue['reason'] = i["message"].to_s
                issue['severity'] = i["severity"].to_s
                issue['isNew'] = i["isNew"].to_s
                issue['startLine'] = i["startLine"].to_s
                issue['endLine'] = i["endLine"].to_s
                issue['status'] = i["status"].to_s
                issues.push(issue)
            }
        return issues.
            select {|issue| issue["isNew"] == "true" && issue["status"] == "OPEN"}
    end

    # Find swift files from the files glob
    # If files are not provided it will use git modifield and added files
    #
    # @return [Array] swift files
    def find_files(files=nil, excluded_paths=[])
      # Assign files to lint
      files = files ? Dir.glob(files) : (git.modified_files - git.deleted_files) + git.added_files

      # Filter files to lint
      return files.
        # Make sure we don't fail when paths have spaces
        map { |file| Shellwords.escape(file) }.
        # Remove dups
        uniq.
        map { |file| File.expand_path(file) }.
        # Reject files excluded on configuration
        reject { |file|
          excluded_paths.any? { |excluded_path|
            Find.find(excluded_path).
              map { |excluded_file| Shellwords.escape(excluded_file) }.
              include?(file)
          }
        }
    end

    # Parses the configuration file and return the excluded files
    #
    # @return [Array] list of files excluded
    def excluded_files_from_config(filepath)
      config = if filepath
        YAML.load_file(config_file)
      else
        {"excluded" => []}
      end

      excluded_paths = config['excluded'] || []

      # Extract excluded paths
      return excluded_paths.
        map { |path| File.join(File.dirname(config_file), path) }.
        map { |path| File.expand_path(path) }.
        select { |path| File.exists?(path) || Dir.exists?(path) }
    end

    # Create a markdown table from Sonar issues
    #
    # @return  [String]
    def markdown_issues (results, heading)
      message = "#### #{heading}\n\n"

      message << "File | Line | Reason |\n"
      message << "| --- | ----- | ----- |\n"
      puts "Markdown resutls: #{results}"
      results.each do |r|
        filename = r['file'].split('/').last
        line = r['line']
        reason = r['reason']

        message << "#{filename} | #{line} | #{reason} \n"
      end

      message
    end

    # Send inline comment with danger's warn or fail method
    #
    # @return [void]
    def send_inline_comment (results, method)
      dir = "#{Dir.pwd}/"
      results.each do |r|
	       filename = r['file'].gsub(dir, "")
	       send(method, r['reason'], file: filename, line: r['line'])
      end
    end

    def log(text)
      puts(text) if @verbose
    end
  end
end
