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

require 'cli/common'
require 'uaa'

module CF::UAA

class ClientCli < CommonCli

  topic "Client Application Registrations"

  CLIENT_SCHEMA =
  {
    scope: "list",
    authorized_grant_types: "list",
    authorities: "list",
    access_token_validity: "seconds",
    refresh_token_validity: "seconds",
    redirect_uri: "list"
  }

  CLIENT_SCHEMA.each { |k, v| define_option(k, "--#{k} <#{v}>") }

  desc "clients", "List client registrations" do
    return unless reglist = client_reg_request { |cr| cr.list }
    pp reglist.each_with_object({}) { |(k, v), o| o[k] = ClientReg.multivalues_to_strings!(v) }
  end

  desc "client get [name]", "Get specific client registration" do |name|
    pp client_reg_request { |cr| ClientReg.multivalues_to_strings!(cr.get(clientname(name))) }
  end

  define_option :clone, "--clone <other_client>", "get default client settings from existing client"
  define_option :interact, "--[no-]interactive", "-i", "interactively verify all values"

  desc "client add [name]", "Add client registration",
      CLIENT_SCHEMA.keys + [:clone, :secret, :interact] do |name|
    client_reg_request do |cr|
      opts[:client_id] = clientname(name)
      opts[:secret] = verified_pwd("New client secret", opts[:secret])
      defaults = opts[:clone] ? cr.get(opts[:clone]) : {}
      cr.create client_info(defaults, opts[:interact])
    end
  end

  desc "client update [name]", "Update client registration",
      CLIENT_SCHEMA.keys + [:interact] do |name|
    client_reg_request do |cr|
      opts[:client_id] = clientname(name)
      defaults = opts[:interact] ? cr.get(opts[:client_id]) : {}
      info = client_info(defaults, opts[:interact])
      return cr.update info if info.length > 1
      say "No options given, nothing to update. Use -i for interactive update."
    end
  end

  desc "client delete [name]", "Delete client registration" do |name|
    client_reg_request { |cr| cr.delete(clientname(name)) }
  end

  desc "secret set [name]", "Set client secret", [:secret] do |name|
    client_reg_request do |cr|
      cr.change_secret(clientname(name), verified_pwd("New secret", opts[:secret]))
    end
  end

  define_option :old_secret, "-o", "--old_secret <secret>", "current secret"
  desc "secret change", "Change secret for authenticated client in current context", [:old_secret, :secret] do
    return say "context not set" unless client_id = Config.context.to_s
    client_reg_request do |cr|
      old = opts[:old_secret] || ask_pwd("Current secret")
      cr.change_secret(client_id, verified_pwd("New secret", opts[:secret]), old)
    end
  end

  def client_reg_request
    return yield ClientReg.new(Config.target, auth_header)
  rescue TargetError => e
    say "\n#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    say "\n#{e.class}: #{e.message}", (e.backtrace if trace?)
  end

  def client_info(defaults, interact)
    del_op = "<delete>"
    info = {client_id: opts[:client_id]}
    info[:client_secret] = opts[:secret] if opts[:secret]
    CLIENT_SCHEMA.each_with_object(info) do |(k, p), info|
      v = nil
      if !opts.key?(k)
        info[k] = (v unless v == del_op) if interact ?
            !p.empty? && (v = askd("#{k.to_s.gsub('_', ' ')} (#{p})", defaults[k])) : (v = defaults[k])
      elsif opts[k] == del_op
        info[k] = nil
      else
        info[k] = v if (v = (opts[k].nil? || opts[k].empty? ? defaults[k]: opts[k]))
      end
    end
  end

end

end
