# danger-sonar

A danger plugin to check for Sonar Qube violation.

## Installation

    $ gem install danger-sonar

## Usage

    Methods and attributes from this plugin are available in
    your `Dangerfile` under the `sonar` namespace.

    Simply add below line to your Dangerfile:

    ```ruby
    sonar.json_report_file = 'sonar-report.json'
    sonar.lint_files
    ```

    For inline comments in your PR, add below line to your Dangerfile:

    ```ruby
    sonar.lint_files inline_mode:true
    ```

    To lint selected files, add below line to your Dangerfile:

    ```ruby
    sonar.lint_files [filename1, filename2, filename3,...]
    ```

    To change messages, add below lines to your Dangerfile:

    ```ruby
    sonar.failure_message = "Sonar lint fialed due to violations, fix them to merge your PR"
    sonar.warning_message = "Fix Sonar violtions"
    ```

    To write custom rules based on Sonar violations, use below properties to get violations count
    ```ruby
    # To read blocker violations count
    sonar.blocker_count 
    # To read critical violations count
    sonar.critical_count
    # To read major violations count
    sonar.major_count
    # To read minor violations count
    sonar.minor_count > 0
    ```

## License
    MIT    

## Development

1. Clone this repo
2. Run `bundle install` to setup dependencies.
3. Run `bundle exec rake spec` to run the tests.
4. Use `bundle exec guard` to automatically have tests run as you make changes.
5. Make your changes.
