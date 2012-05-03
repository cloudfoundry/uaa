#--
# Cloud Foundry 2012.02.03 Beta
# Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache License, Version 2.0 (the "License").
# You may not use this product except in compliance with the License.
#
# This product includes a number of subcomponents with
# separate copyright notices and license terms. Your use of these
# subcomponents is subject to the terms and conditions of the
# subcomponent's license, as noted in the LICENSE file.
#++

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
#  command, command_args, options, result = CF::UAA::OptParser.parse(args)
#  return result if !result
#  execute()
#
# If the result is false the usage and help will already have been
# output to the console.
class CF::UAA::OptParser

  # The name of the command (for usage banner)
  NAME = 'uaa'
  COMMANDS = %w(help target prompts login decode register)

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

    if @args.nil? || @args.empty?
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
  Usage: #{NAME} [options] <command> [<args>] [command_options]
     or: #{NAME} help <command>
         <command> can be one of help, target, prompts, login, decode, register
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
      opts.version = CF::UAA::VERSION

      opts.on('--target TARGET', 'Use the specified target instead of the one set with the target command') do |target|
        @options[:target] = target
      end

      opts.on('--client_id CLIENT_ID', '--client-id', 'Use the specified client_id to authenticate') do |client_id|
        @options[:client_id] = client_id
      end

      opts.on('--client_secret CLIENT_SECRET', '--client-secret', 'Use the specified client_secret to authenticate') do |client_secret|
        @options[:client_secret] = client_secret
      end

      opts.on('--verbose', '--trace', 'Run verbosely') do
        @options[:verbose] = true
      end

      opts.on_tail("-h", "--help", "Show this message") do
        @command = :help
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
  Usage: #{NAME} login [options] [username] [password] [login_options]
         Arguments that are not provided will be prompted for as necessary
Login Options:
EOF
        opts.on('-s', '--scope SCOPE', 'Set the scope of the token request (space or comma separated list)') do |scope|
          if scope.include? " " then
            @options[:scope] = scope.split(" ")
          else
            @options[:scope] = scope.split(",")
          end
        end
        opts.on('-g', '--grant_type TYPE', '--grant-type TYPE', 'Set the grant type of the token request (available as supported by server for this client)') do |grant_type|
          @options[:grant_type] = grant_type
        end
        opts.on('-r', '--redirect_uri URI', '--redirect-uri URI', 'Set the redirect uri') do |uri|
          @options[:redirect_uri] = uri
        end
        @options[:save_token] = true
        opts.on('-s', '--[no-]save-token', 'If set (') do |save_token|
          @options[:save_token] = save_token
        end

      when :decode
        opts.banner = <<-EOF
  Usage: #{NAME} [options] decode [token]
         The token is optional (defaults) to the token obtained when logging in.
         If the token was obtained with an untrusted client you will need to
         supply new client_id and client_secret global options to decode a token.
EOF

      when :register
        opts.banner = <<-EOF
  Usage: #{NAME} register [email] [username] [given_name] [family_name] [password]

         email:        email address for the new new account
         username:     username for the new new account
         family_name:  family name for the new account
         given_name:   given name for the new account
         password:     password for the new new account

  Arguments that are not provided will be prompted for as necessary

  Options:

EOF
        opts.on('-n', '--name NAME', 'The full name of the new account (defaults to "given_name family_name")') do |name|
          @options[:name] = name
        end
      end

    end

    opts_parser.parse!(@command_args)
    opts_parser

  end

  def parse_command()

    command = @command_args.shift
    if COMMANDS.include?(command)
      @command = command.intern
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

    when :register
      @options[:email] = @command_args[0] if @command_args.length>0
      @options[:username] = @command_args[1] if @command_args.length>1
      @options[:given_name] = @command_args[2] if @command_args.length>2
      @options[:family_name] = @command_args[3] if @command_args.length>3
      @options[:password] = @command_args[4] if @command_args.length>4

    end

    result

  end

end
