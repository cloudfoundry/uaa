require 'optparse'
require 'uaa/version'

# Parser for Uaa command line options. The input should be in the form
#
#   [global_options]* [command] [command_args]* [command_options]*
#
# and each of those will be separated out and analysed.  If the input
# is in the wrong form or if help is requested explicitly with the
# :help command or with '-h' or '--help' global options, then the
# caller can extract a false result and stop further processing.  E.g.
#
#  command, command_args, options, result = Cloudfoundry::Uaa::OptParser.parse(args)
#  return result if !result
#  execute()
#
# If the result is false the usage and help will already have been
# output to the console.
class Cloudfoundry::Uaa::OptParser

  # The name of the command (for usage banner)
  NAME = 'uaa'
  COMMANDS = %w(help target prompts login decode)

  class HelpRequiredException < StandardError
    def to_s
      "Help for #{NAME} #{super.to_s}"
    end
  end

  # Create a new instance
  def initialize(args=[])
    @args = args
    @global_args = []
    @command_args = []
    @result = nil
    @options = {:verbose=>false}
  end

  # Convenience class method to allow parsing of command and options.
  # See #parse for details.
  def self.parse(args)
    new(args).parse()
  end

  # Parse the arguments supplied during initialization and return a
  # tuple in the form
  #
  #   command, command_args, options, result
  #
  # * +command+ - a symbol representing the command to execute
  # * +command_args+ - an array of arguments for the command
  # * +options+ - a hash of options as requested by command line
  #   switches (arguments beginning with '-')
  # * +result+ - a flag, true or false (or possibly nil) according
  #   to whether the parsing was successful
  #
  # If the result is false then the command cannot be extracted or the
  # user asked for help. Help is output on the console.
  def parse()

    opts_parser = global_opts_parser

    if @args.empty?
      @result = false
      raise HelpRequiredException, "(no command provided)"
    end

    @global_args, @command_args = extract_command_args(@args)
    opts_parser.parse!(@global_args)

    opts_parser = parse_command() unless @command
    if @command==:help
      @result = false
      opts_parser = parse_command()
      raise HelpRequiredException, "help requested"
    end

    @result = true if @result.nil?

    [@command, @command_args, @options, @result]

  rescue HelpRequiredException, OptionParser::InvalidOption, OptionParser::MissingArgument
    puts $!.to_s
    puts opts_parser
    @result = false if @result.nil?
    [@command, @command_args, @options, @result]

  end

  private

  def basic_usage
    <<-EOF
  Usage: #{NAME} [options] command [<args>] [command_options]
     or: #{NAME} help command
EOF
  end

  def basic_usage_with_options
    <<-EOF
#{basic_usage}
Options:
EOF
  end

  def global_opts_parser

    opts_parser = OptionParser.new do |opts|

      opts.banner = basic_usage_with_options
      opts.version = Cloudfoundry::Uaa::VERSION

      opts.on('--client_id CLIENT_ID', 'Use the specified client_id to authenticate') do |client_id|
        @options[:client_id] = client_id
      end

      opts.on('--client_secret CLIENT_SECRET', 'Use the specified client_secret to authenticate') do |client_secret|
        @options[:client_secret] = client_secret
      end

      opts.on('--verbose', 'Run verbosely') do
        @options[:verbose] = true
      end

      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        @result = true
      end

      opts.on_tail("-v", "--version", "Show version") do
        puts opts.ver
        @result = true
      end

    end

    opts_parser

  end

  def extract_command_args(args)
    afters = []
    afters = args.drop_while { |item| !COMMANDS.include? item }
    befores = args - afters
    [befores,afters]
  end

  def parse_command_options()

    opts_parser = OptionParser.new do |opts|

      opts.banner = basic_usage

      case @command
      when :target
        opts.banner = "Usage: #{NAME} [options] target url"
      when :login
        opts.banner = <<-EOF
  Usage: #{NAME} [options] login [username] [password]
Options:
EOF
        opts.on('-s', '--scope SCOPE', 'Set the scope of the token request (space or comma separated list)') do |scope|
          if scope.include? " " then
            @options[:scope] = scope.split(" ")
          else
            @options[:scope] = scope.split(",")
          end
        end
        opts.on('-g', '--grant_type TYPE', 'Set the grant type of the token request (available as supported by server for this client)') do |grant_type|
          @options[:grant_type] = grant_type
        end
      when :decode
        opts.banner = "Usage: #{NAME} decode token"
      end

    end

    opts_parser.parse!(@command_args)
    opts_parser

  end

  def parse_command()

    case @command_args.shift
    when 'help'
      @command = :help
    when 'target'
      @command = :target
    when 'login'
      @command = :login
    when 'decode'
      @command = :decode
    when 'prompts'
      @command = :prompts
    else
      @result = false if @result.nil?
      raise HelpRequiredException, '(no command or invalid command specified)'
    end

    result = parse_command_options()

    # Validate additional args here if necessary
    case @command
    when :login
      @options[:username] = @command_args[0] if @command_args.length>0
      @options[:password] = @command_args[1] if @command_args.length>1
    end

    result

  end

end
