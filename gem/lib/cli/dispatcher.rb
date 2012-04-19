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
require 'json/pure'

require 'uaa'

# Useful abstraction to separate command line wrapper from the actual
# client code. Takes a command and dispatches it to the client.
class CF::UAA::Dispatcher

  attr_accessor :client
  attr_writer :target_file

  def initialize(options={})
    @client = options[:client] || CF::UAA::Client.new
    @target_file = options[:target_file] || File.join(ENV['HOME'], '.uaa_target')
    @token_file = options[:token_file] || File.join(ENV['HOME'], '.uaa_tokens')
    init_target
  end

  def dispatch(command, args=[], options={})

    unless options[:target].nil? then
      @client.target = fix_target(options[:target])
    end

    @client.debug = true if options[:verbose]
    save_token = options[:save_token]

    options = options.dup
    # These are just options for the dispatcher (so the clietn doesn't ned them)
    options.delete :verbose
    options.delete :save_token

    case command
    when :target
      save_target(args[0])
    when :login
      token = @client.login(options)
      save_token(token) if token && save_token
      token
    when :register
      @client.register(options)
    when :decode
      @client.decode_token(args[0], options)
    when :prompts
      @client.prompts()
    else
      raise StandardError, "Command cannot be dispatched: #{command}"
    end

  end

  private

  def init_target(target=nil)
    file = @target_file
    @client.target = File.open(file).read unless !File.exist? file
    if @client.target
      file = @token_file
      @client.token = json_parse(File.open(file).read)[@client.target] unless !File.exist? file
    end
  end

  def save_target(target)
    return @client.target if target.nil?
    # TODO: use https by default?
    target = fix_target target
    return @client.target if @client.target == target
    file = File.open(@target_file, 'w')
    file.write target
    file.close
    @client.target = target
  end

  def fix_target(target)
    target = "http://#{target}" if target !~ /^http.*:\/\//
    target
  end

  def save_token(token)
    return @client.token if token.nil?
    return @client.token if @client.token == token
    tokens = File.exist?(@token_file) ? json_parse(File.open(@token_file).read) : {}
    tokens[@client.target] = token
    file = File.open(@token_file, 'w')
    file.write tokens.to_json
    file.close
    @client.token = token
  end

  def json_parse(str)
    if str
      JSON.parse(str, :symbolize_names => false)
    end
  end

end
