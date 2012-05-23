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
require 'cli/login'
require 'cli/user'
require 'cli/client_reg'

module CF::UAA

class TCli < BaseCli

  desc "version", "Display version"
  map "v" => "version", "-v" => "version", "--version" => "version"
  def version
    puts "UAA client #{VERSION}"
  end

  desc "help [command]", "Display command summary or details of one command"
  def help(task = nil, subcommand = false)
    task ? self.class.task_help(shell, task) : self.class.help(shell, subcommand)
    puts "All commands and subcommands can be abbreviated with the first character.", "" unless task
  end

  desc "client [add, del, list, update]", "operations on client registrations"
  map "c" => "client"
  subcommand "client", ClientCli

  desc "user [add, del, find, pwd, ...]", "operations on user accounts"
  map "u" => "user"
  subcommand "user", UserCli

  desc "login [client, implicit, code, ...]", "operations on oauth tokens"
  map "l" => "login"
  subcommand "login", LoginCli

  desc "target [#] or [uaa_url client_id]", "display or set target UAA instance"
  map "t" => "target"
  method_option :force, type: :boolean, aliases: "-f", desc: "store info even if target not available"
  def target(uaa_url = nil, client_id = File.basename($0))
    return help(__method__) if help?
    if uaa_url && uaa_url.to_i.to_s == uaa_url
      Config.target = uaa_url.to_i
    elsif uaa_url
      uaa_url = Util.normalize_url(uaa_url)
      begin
        CF::UAA::TokenIssuer.new(uaa_url, client_id, nil, nil, opts[:trace]).prompts
      rescue Exception => e
        puts "failed to access #{uaa_url}: #{e.message}"
        return unless opts[:force]
        puts "saving target anyway due to --force option"
      end
      Config.target = target_key(uaa_url, client_id)
    end
    puts cur_target_url ? "target set to: #{cur_target_url} #{cur_client_id}" : "no target set"
  end

  desc "settings", "display or set info for the current target"
  method_option :scope, type: :string, aliases: "-s", lazy_default: "", desc: "set default token scope"
  method_option :client_secret, type: :string, aliases: "-c", lazy_default: "", desc: "set client secret"
  map "s" => "settings"
  def settings
    return help(__method__) if help?
    opts[:client_secret] = ask("Client secret") if opts[:client_secret] == ""
    opts[:scope] = ask("Scope list") if opts[:scope] == ""
    new_opts = [:trace, :scope, :client_secret].each_with_object({}) { |k, o|
        o[k] = opts[k] if opts.key?(k) }
    Config.opts(new_opts)
    Config.config.each_with_index do |(k, v), i|
      next unless opts[:verbose] || v[:current_target]
      splat = v[:current_target] ? '*' : ' '
      v.delete(:current_target)
      puts "[#{i}]#{splat}[#{Util.unrubyize_key(k)}]"
      pp v, 1
    end
  end

  desc "remove [targets...]", "remove current or specific target tokens and settings"
  method_option :logout, type: :boolean, aliases: "-l", desc: "logout only (remove token)"
  def remove(*args)
    key = (:token if opts[:logout])
    return help(__method__) if help?
    return Config.delete_target(Config.target, key) if args.empty?
    args.each do |arg|
      begin
        tgt = arg.split(' ')
        raise ArgumentError, "invalid target #{arg}" if tgt.length > 2
        Config.delete_target(Config.find_target(t[0], t[1]), key)
      rescue ArgumentError => e
        puts e.message
      end
    end
  end

  private

  def target_key(uaa_url, client_id)
    "#{Util.normalize_url(uaa_url)} #{client_id}".to_sym
  end

end

end
