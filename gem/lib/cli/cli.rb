require 'highline'

require 'cli/dispatcher'
require 'cli/optparse'
require 'uaa/error'

# Commandline framework.  Parses subcommands and options passed on the
# command line and dispatches them.
class Cloudfoundry::Uaa::Cli

  attr_reader   :command
  attr_reader   :options
  attr_writer   :dispatcher
  attr_writer   :terminal

  def initialize(args=[])
    @args = args
    @command_args = []
    @options = {}
    @result = nil
    @command = nil
    @dispatcher = Cloudfoundry::Uaa::Dispatcher.new
    @terminal = HighLine.new
  end

  # Main entry point for command line clients. Caller supplies command
  # arguments line as a string.
  def self.run(args)
    trap('TERM') { print "\nTerminated\n"; exit(false)}
    result = new(args).run
    if result then
      puts result
      exit true
    end
    exit false
  end

  # Run the command indicated in the arguments provided during
  # initialization.  Return a JSON literal, or a plain String, or nil
  # depending on the outcome.  A nil or false result indicates an
  # error.
  def run

    @command, @command_args, @options, result = Cloudfoundry::Uaa::OptParser.parse(@args)
    if @options[:verbose] then
      puts "Command: #{@command}"
      puts "Args: #{@command_args}"
      puts "Options: #{@options}"
    end
    return result if !result

    begin
      execute()
    rescue Cloudfoundry::Uaa::PromptRequiredError => bang
      retry if prompt_for_missing_options(bang.prompts)
    end

  ensure
    @result = true if @result.nil?
    if @options[:verbose]
      if @result
        puts "Command: #{@command} SUCCEEDED"
      else
        puts "Command: #{@command} FAILED"
      end
    end
  end

  private

  def prompt_for_missing_options(prompts)
    old_options = @options.dup
    prompts.keys.each do |key|
      unless @options[key] then
        prompt = prompts[key]
        echo = true
        if prompt[0]=="password" then
          echo = "*"
        end 
        value = @terminal.ask("#{prompt[1]}: ") { |q| q.echo = echo }
        @options[key] = value
      end
    end
    return @options != old_options
  end

  def strip_quotes(result)
    if /^"(.*?)"$/ =~ result then
      result = result.gsub!(/^"(.*?)"$/,'\1')
    end
    result
  end

  def execute()

    @result = @dispatcher.dispatch(@command, @command_args, @options)

    if !@result.nil? then
      @result = strip_quotes(@result.to_json)
    end

    @result = true if @result.nil?
    @result

  end

end
