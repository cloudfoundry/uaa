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

  desc "get [name]", "get client registration info."
  map "g" => "get"
  def get(name = cur_client_id)
    return help(__method__) if options[:help]
    pp client_reg_request { |cr| cr.get(name) }
  end

  desc "add [name]", "add client registration."
  method_option :clone, type: :string, aliases: "-c", desc: "get default client settings from existing client."
  method_option :secret, type: :string, aliases: "-s", desc: "set client secret"
  map "a" => "add"
  def add(name = nil)
    return help(__method__, "client") if options[:help]
    name ||= ask("New client name")
    secret = verified_pwd("New client secret", options['secret'])
    clone = options[:clone]
    client_reg_request do |cr|
      defaults = clone ? cr.get(clone) : {}
      scopes, resource_ids, grant_types, roles, redir_uris = client_info(defaults)
      cr.create(name, secret, scopes, resource_ids, grant_types, roles, redir_uris)
    end
  end

  desc "update [name]", "update client registration info."
  method_option :secret, type: :string, aliases: "-s", lazy_default: "", desc: "update client secret, prompts if not given"
  map "u" => "update"
  def update(name)
    return help(__method__) if options[:help]

    # TODO: after uaa allows partial update of client, this can use the -s option
    secret = verified_pwd("new client secret", secret == ""? nil: secret, "") # if secret = options[:secret]
    client_reg_request do |cr|
      defaults = cr.get(name)
      scopes, resource_ids, grant_types, roles, redir_uris = client_info(defaults)
      cr.update(name, secret, scopes, resource_ids, grant_types, roles, redir_uris)
    end
  end

  desc "delete [name]", "delete client registration info"
  map "d" => "delete"
  def delete(name = nil)
    return help(__method__) if options[:help]
    name ||= ask("Client name")
    pp client_reg_request { |cr| cr.delete(name) }
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
    scopes = askd("Supported scopes", defaults[:scope])
    resource_ids = askd("Authorized resource IDs", defaults[:resource_ids])
    grant_types = askd("Authorized grant types", defaults[:authorized_grant_types])
    roles = askd("Roles", defaults[:authorities])
    redir_uris = askd("Authorized redirection URIs", defaults[:redirect_uri])
    [scopes, resource_ids, grant_types, roles, redir_uris]
  end

end

end
