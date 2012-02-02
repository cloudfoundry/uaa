require 'optparse'

require 'uaa'

# Useful abstraction to separate command line wrapper from the actual
# client code. Takes a command and dispatches it to the client.
class Cloudfoundry::Uaa::Dispatcher

  attr_accessor :client
  attr_writer :target_file

  def initialize(options={})
    @client = options[:client] || Cloudfoundry::Uaa::Client.new
    @target_file = options[:target_file] || File.join(ENV['HOME'], '.uaa_target')
    init_target
  end

  def dispatch(command, args=[], options={})
    @client.trace = true if options[:verbose] 
    case command
    when :target
      save_target(args[0])
    when :login
      @client.login(options)
    when :decode
      @client.decode_token(args[0], options)
    when :prompts
      @client.prompts()
    else
      raise StandardError, "Command cannot be dispatched: #{command}"
    end
  end

  private

  def init_target
    file = @target_file
    @client.target = File.open(file).read unless !File.exist? file
  end

  def save_target(target)
    return @client.target if target.nil?
    # TODO: use https by default?
    target = "http://#{target}" if target !~ /^http.*:\/\//
    return @client.target if @client.target == target
    file = File.open(@target_file, 'w')
    file.write target
    file.close
    @client.target = target
  end

end
