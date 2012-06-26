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

require 'thor'
require 'interact'
require 'cli/config'

module CF::UAA

class BaseCli < Thor
  include Interactive
  include Interactive::Rewindable

  def self.run(config_file = nil, args = ARGV, opts = {})
    Config.start config_file
    start args, opts
  end

  def self.terminal_columns
    puts __FILE__ + __LINE__
    return @terminal_columns if @terminal_columns
    return @terminal_columns = 0 unless $stdout.isatty
    cols = ENV['COLUMNS'] ? ENV['COLUMNS'].to_i :
        (`stty size 2>/dev/null`.split[1].to_i rescue `tput cols 2>/dev/null`.to_i rescue 0)
    @terminal_columns = !cols || cols < 8 ? 0 : cols
  end

  def self.pp(obj, indent_count = 0, indent_size = 4, line_limit = terminal_columns, label = nil)
    line = ""
    indent_count.times { line << sprintf("%*c", indent_size, ' ') }
    line << label if label
    if obj.is_a? Array
      puts Util.truncate(line, line_limit) if label
      label = sprintf "%-*c", indent_size, '-'
      obj.each {|o| pp o, indent_count, indent_size, line_limit, label }
    elsif obj.is_a? Hash
      if label
        puts Util.truncate(line, line_limit)
        indent_count += 1
      end
      obj.each { |k, v| pp v, indent_count, indent_size, line_limit, "#{k}: " }
    else
      puts Util.truncate(line << obj.to_s, line_limit)
    end
  end

  class_option :trace, type: :boolean, aliases: "-t", desc: "display debug information"
  class_option :verbose, type: :boolean, aliases: "-V", desc: "verbose"
  class_option :help, type: :boolean, aliases: "-h", desc: "help"

  private

  def opts
    return @all_options if @all_options
    @all_options = {}
    @all_options.merge!(options) if options
    @all_options.merge!(parent_options) if parent_options
    @all_options = Util.hash_keys(@all_options, :tosym)
  end

  def trace?
    opts.key?(:trace) ? opts[:trace] : Config.opts[:trace]
  end

  def help?
    opts[:help]
  end

  def pp(obj, indent_count = 0)
    self.class.pp obj, indent_count
  end

  def cur_target_url
    Config.target.to_s.split[0] if Config.target
  end

  def cur_client_id
    Config.target.to_s.split[1] if Config.target
  end

  def auth_header
    unless (token = Config.opts[:token]) && token[:token_type] && token[:access_token]
      puts "Need an access token to complete this command. Please login."
      exit 9
    end
    "#{token[:token_type]} #{token[:access_token]}"
  end

  def verified_pwd(prompt, pwd, default = nil)
    while pwd.nil?
      pwd_a = ask prompt, echo: "*", forget: true, default: default
      pwd_b = ask "Verify #{prompt}", echo: "*", forget: true, default: default
      pwd = pwd_a if pwd_a == pwd_b
    end
    pwd
  end

  def name_pwd(username, pwd)
    [ username || ask("User name"), verified_pwd("Password", pwd) ]
  end

end

end
