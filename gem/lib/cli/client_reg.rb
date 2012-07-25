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

  topic "Client application registrations"

  CLIENT_SCHEMA =
  {
    scopes: "list",
    resource_ids: "list",
    authorized_grant_types: "list",
    authorities: "list",
    access_token_validity: "seconds",
    refresh_token_validity: "seconds",
    redirect_uris: "list"
  }

  CLIENT_SCHEMA.each { |k, v| define_option(k, "--#{k} <#{v}>") }

  desc "clients", "List client registrations" do
    reglist = client_reg_request { |cr| cr.list }
    reglist.each { |k, v| reglist[k] = ClientReg.multivalues_to_strings!(v) }
    pp reglist
  end

  desc "client get [<name>]", "Get specific client registration" do |name|
    name ||= cur_client_id
    pp client_reg_request { |cr| ClientReg.multivalues_to_strings!(cr.get(name)) }
  end

  define_option :clone, "--clone <other_client>", "get default client settings from existing client"
  define_option :secret, "--secret <secret>", "client secret"
  define_option :interact, "--[no-]interactive", "-i", "interactively verify all values"

  desc "client add [<name>]", "Add client registration",
      CLIENT_SCHEMA.keys + [:clone, :secret, :interact] do |name|
    opts[:client_id] ||= name || ask("New client name")
    opts[:client_secret] = verified_pwd("New client secret", opts[:secret])
    client_reg_request do |cr|
      defaults = opts[:clone] ? cr.get(opts[:clone]) : {}
      cr.create client_info(defaults, opts[:interact])
    end
  end

  desc "client update [<name>]", "Update client registration",
      CLIENT_SCHEMA.keys + [:secret, :interact] do |name|
    opts[:client_id] ||= name || ask("Client name")
    client_reg_request do |cr|
      defaults = opts[:interact] ? cr.get(opts[:client_id]) : {}
      cr.update client_info(defaults, opts[:interact])
    end
  end

  desc "client secret [<name>]", "Update client secret", [:secret] do |name|
    say "update client secret not implemented"
    #opts[:client_id] ||= name || ask("Client name")
    #client_reg_request do |cr|
      #defaults = opts[:interact] ? cr.get(opts[:client_id]) : {}
      #cr.update client_info(defaults, opts[:interact])
    #end
  end

  desc "client delete [<name>]", "Delete client registration" do |name|
    name ||= ask("Client name")
    pp client_reg_request { |cr| cr.delete(name) }
  end

  def client_reg_request
    return yield ClientReg.new(Config.target, auth_header)
  rescue TargetError => e
    say "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
    nil
  rescue Exception => e
    say "#{e.class}, #{e.message}", (e.backtrace if trace?)
    nil
  end

  def client_info(defaults, interact)
    del_op = "<delete>"
    info = {client_id: opts[:client_id]}
    info[:client_secret] = opts[:secret] if opts[:secret]
    CLIENT_SCHEMA.each_with_object(info) do |(k, p), info|
      v = nil
      if !opts.key?(k)
        info[k] = (v unless v == del_op) if interact ?
            !p.empty? && (v = askd(p, defaults[k])) : (v = defaults[k])
      elsif opts[k] == del_op
        info[k] = nil
      else
        info[k] = v if (v = (opts[k].nil? || opts[k].empty? ? defaults[k]: opts[k]))
      end
    end
  end

end

end
