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
require 'cli/base'
require 'uaa'

module CF::UAA

class ClientCli < BaseCli

  namespace :client

  def self.banner(task, namespace = true, subcommand = true)
    "#{basename} #{task.formatted_usage(self, true, subcommand)}"
  end

  def self.client_info_schema
    {
      client_id: "Client ID",
      client_secret: "",
      scope: "Scope list",
      resource_ids: "Resource ID list",
      authorized_grant_types: "Authorized grant type list",
      authorities: "Role list",
      access_token_validity: "Access token lifetime",
      refresh_token_validity: "Refresh token lifetime",
      redirect_uri: "Redirect URI list"
    }
  end

  def self.client_info_options
    client_info_schema.each do |k, v|
      next if v.empty?
      method_option k, type: :string, lazy_default: "", desc: v
    end
  end

  desc "get [name]", "get client registration info."
  map "g" => "get"
  def get(name = cur_client_id)
    return help(__method__) if help?
    pp client_reg_request { |cr| ClientReg.multivalues_to_strings!(cr.get(name)) }
  end

  desc "add [name]", "add client registration."
  method_option :clone, type: :string, aliases: "-c", desc: "get default client settings from existing client."
  method_option :secret, type: :string, aliases: "-s", lazy_default: "", desc: "client secret"
  client_info_options
  map "a" => "add"
  def add(name = nil)
    return help(__method__) if help?
    opts[:client_id] ||= name || ask("New client name")
    opts[:client_secret] = verified_pwd("New client secret", opts[:secret] == ""? nil: opts[:secret])
    client_reg_request do |cr|
      defaults = opts[:clone] ? cr.get(opts[:clone]) : {}
      cr.create client_info(defaults)
    end
  end

  desc "update [name]", "update client registration info."
  method_option :secret, type: :string, aliases: "-s", lazy_default: "", desc: "client secret, prompts if not given"
  client_info_options
  map "u" => "update"
  def update(name = cur_client_id)
    return help(__method__) if help?
    opts[:client_id] ||= name
    opts[:client_secret] = verified_pwd("new client secret", opts[:secret] == ""? nil: opts[:secret]) if opts[:secret]
    client_reg_request do |cr|
      defaults = cr.get(opts[:client_id])
      cr.update client_info(defaults)
    end
  end

  desc "delete [name]", "delete client registration info"
  map "d" => "delete"
  def delete(name = nil)
    return help(__method__) if help?
    name ||= ask("Client name")
    pp client_reg_request { |cr| cr.delete(name) }
  end

  desc "list", "list client registrations"
  map "l" => "list"
  def list
    return help(__method__) if help?
    reglist =  client_reg_request { |cr| cr.list }
    reglist.each { |k, v| reglist[k] = ClientReg.multivalues_to_strings!(v) }
    pp reglist
  end

  desc "tokens [clientname]", "list tokens granted to client"
  map "t" => "tokens"
  def tokens(name = nil)
    return help(__method__) if help?
    name ||= ask("Client name")
    pp client_reg_request { |cr| cr.list_tokens(name) }
  end

  desc "revoke client_name token_id", "revoke token"
  map "r" => "revoke"
  def revoke(name, token_id)
    return help(__method__) if help?
    pp client_reg_request { |cr| cr.revoke_token(name, token_id) }
  end

  private

  def client_reg_request
    return yield ClientReg.new(cur_target_url, auth_header, trace?)
  rescue TargetError => e
    puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    puts "#{e.class}, #{e.message}", (e.backtrace if trace?)
  end

  def askd(prompt, defary)
    ask(prompt, default: (defary.join(' ') if defary && defary.respond_to?(:join)))
  end

  def client_info(defaults)
    del_op = "<delete>"
    self.class.client_info_schema.each_with_object({}) do |(k, p), info|
      v = nil
      if !opts.key?(k)
        (info[k] = (v unless v == del_op)) if !p.empty? && (v = askd(p, defaults[k]))
      elsif opts[k] == del_op
        info[k] = nil
      else
        info[k] = v if (v = (opts[k].nil? || opts[k].empty? ? defaults[k]: opts[k]))
      end
    end
  end

end

end
