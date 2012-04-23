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
require 'uaa'

class CF::UAA::TCli < Thor
  include Interactive
  include Interactive::Rewindable

  class_option :trace, type: :boolean, aliases: "-t", desc: "display debug information"
  class_option :verbose, type: :boolean, aliases: "-v", desc: "verbose"
  class_option :help, type: :boolean, aliases: "-h", desc: "help"

  # a bunch of helpers
  no_tasks do
    def trace?
      options.key?('trace') ? options['trace'] : CliCfg.opts[:default_trace]
    end

    def client_secret
      options[:client_secret] || CliCfg.opts[:client_secret] || ask("Client secret", echo: "*", forget: true)
    end

    def scope
      options[:scope] || CliCfg.opts[:default_scope]
    end

    def auth_header
      "#{CliCfg.opts[:token_type]} #{CliCfg.opts[:access_token]}"
    end

    def issuer_request(csecret = client_secret)
      return yield CF::UAA::TokenIssuer.new(CliCfg.target, CliCfg.client_id, csecret, scope, trace?)
    rescue CF::UAA::TargetError => e
      puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
    rescue Exception => e
      puts e.message, (e.backtrace if trace?)
    end

    def verified_pwd(prompt, pwd)
      while pwd.nil?
        pwd_a = ask(prompt, echo: "*", forget: true)
        pwd_b = ask("Verify #{prompt}", echo: "*", forget: true)
        pwd = pwd_a if pwd_a == pwd_b
      end
      pwd
    end

    def name_pwd(username, pwd)
      [ username || ask("User name"), verified_pwd("Password", pwd) ]
    end

    def acct_request
      return yield CF::UAA::UserAccount.new(CliCfg.target, auth_header, trace?)
    rescue CF::UAA::TargetError => e
      puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
    rescue Exception => e
      puts e.message, (e.backtrace if trace?)
    end

    def id_request
      return yield CF::UAA::IdToken.new(CliCfg.target, auth_header, trace?)
    rescue CF::UAA::TargetError => e
      puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
    rescue Exception => e
      puts e.message, (e.backtrace if trace?)
    end

    def client_reg_request
      return yield CF::UAA::ClientReg.new(CliCfg.target, auth_header, trace?)
    rescue CF::UAA::TargetError => e
      puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
    rescue Exception => e
      puts "#{e.class}, #{e.message}", (e.backtrace if trace?)
    end
  end

  desc "target [uaa_url] [client_id]", "display or set required info for the desired UAA instance"
  method_option :force, type: :boolean, aliases: "-f", desc: "store info even if target not available"
  method_option :default_trace, type: :boolean, aliases: "-d", desc: "set default trace option"
  method_option :default_scope, type: :string, aliases: "-s", desc: "set default token scope"
  method_option :client_secret, type: :string, aliases: "-c", desc: "set client secret"
  method_option :all, type: :boolean, aliases: "-a", desc: "display info for all targets"
  def target(uaa_url = nil, client_id = File.basename($0))
    return help(__method__) if options.help?
    if uaa_url
      uaa_url = CliCfg.normalize_url(uaa_url)
      url_valid = false
      begin
        toki = CF::UAA::TokenIssuer.new(uaa_url, client_id, nil, nil, options.trace?)
        url_valid = !!toki.prompts
      rescue Exception => e
        puts "failed to access #{uaa_url}: #{e.message}"
      end
      unless url_valid
        return false unless options.force?
        puts "saving target anyway due to --force option"
      end
      CliCfg.set_target uaa_url, client_id
    end
    if CliCfg.target
      new_opts = [:default_trace, :default_scope, :client_secret].each_with_object({}) {|k, o|
        o[k] = options[k.to_s] if options.key?(k.to_s) }
      CliCfg.opts new_opts
      puts "target set to: #{CliCfg.target} #{CliCfg.client_id}"
    else
      puts "no target set"
    end
    if options['all']
      CliCfg.dump
    elsif options.verbose?
      CliCfg.pp CliCfg.opts
    end
  end

  desc "logout [uaa_url] [client_id]", "clear all tokens and settings for a UAA instance, default current target"
  def logout(uaa_url = nil, client_id = nil)
    return help(__method__) if options.help?
    client_id = File.basename($0) if uaa_url && !client_id
    CliCfg.clear_target(uaa_url || CliCfg.target, client_id || CliCfg.client_id)
  end

  desc "prompts", "show prompts for credentials required for implicit grant"
  def prompts
    return help(__method__) if options.help?
    CliCfg.pp issuer_request { |ti| ti.prompts }
  end

  desc "client_credentials", "gets a token with client credentials grant. alias 'cc'"
  method_option :scope, type: :string, aliases: "-s", desc: "requested token scope"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret"
  map "cc" => "client_credentials"
  def client_credentials
    return help(__method__) if options.help?
    CliCfg.opts issuer_request { |ti| ti.client_credentials_grant.info }
  end

  desc "login [credentials...]", "gets a token via implicit grant. alias 'imp' or 'implicit'"
  method_option :scope, type: :string, aliases: "-s", desc: "requested token scope"
  map "imp" => "login", "implicit" => "login"
  def login(*args)
    return help(__method__) if options.help?
    CliCfg.opts issuer_request("n/a") { |ti|
      prompts = ti.prompts
      creds = {}
      prompts.each do |k, v|
        if arg = args.shift
          creds[k] = arg
        elsif v[0] == "text"
          creds[k] = ask(v[1])
        elsif v[0] == "password"
          creds[k] = ask(v[1], echo: "*", forget: true)
        else
          err "Unknown prompt type \"#{v[0]}\" received from #{CliCfg.target}"
        end
      end
      ti.implicit_grant(creds).info
    }
  end

  desc "owner_pwd [username] [pwd]", "gets a token with an owner password grant. alias 'op'"
  map "op" => "owner_password"
  method_option :scope, type: :string, aliases: "-s", desc: "requested token scope"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret"
  def owner_pwd(username = nil, pwd = nil)
    return help(__method__) if options[:help]
    username, pwd = name_pwd(username, pwd)
    CliCfg.opts issuer_request { |ti| ti.owner_password_grant(username, pwd).info }
  end

  desc "refresh [refresh_token]", "gets a new access token from a refresh token"
  method_option :scope, type: :string, aliases: "-s", desc: "requested token scope"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret"
  def refresh(rtoken = CliConfig.opts[:refresh_token])
    return help(__method__) if options[:help]
    CliCfg.opts issuer_request { |ti| ti.refresh_token_grant(rtoken).info }
  end

  desc "token [token] [token_type]", "displays token contents as parsed locally or by the UAA"
  method_option :key, type: :string, aliases: "-k", desc: "token signing key"
  method_option :local, type: :string, aliases: "-l", desc: "parse token locally, validates if --key given"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret for remote token validation"
  def token(token = nil, token_type = nil)
    return help(__method__) if options[:help]
    token_type = "bearer" if token && !token_type
    token ||= CliCfg.opts[:access_token]
    token_type ||= CliCfg.opts[:token_type]
    if options[:local]
      CliCfg.pp CF::UAA::TokenCoder.decode(token, options[:key])
    else
      tkc = CF::UAA::TokenChecker.new(CliCfg.target, CliCfg.client_id, client_secret, trace?)
      CliCfg.pp tkc.decode("#{CliCfg.opts[:token_type]} #{CliCfg.opts[:access_token]}")
    end
  rescue CF::UAA::TargetError => e
    puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    puts e.message
  end

  desc "create [username] [password]", "creates a user account"
  method_option :given_name, type: :string, aliases: "-g"
  method_option :family_name, type: :string, aliases: "-f"
  method_option :email, type: :string, aliases: "-e"
  def create(username = nil, pwd = nil)
    return help(__method__) if options[:help]
    username, pwd = name_pwd(username, pwd)
    email = options[:email] || (username if username =~ /@/)
    gname = options[:given_name] || username
    fname = options[:family_name] || username
    CliCfg.pp acct_request { |ua| ua.create(username, pwd, email, gname, fname) }
  end

  desc "list [attributes] [filter]", "list user accounts"
  def list(attributes = nil, filter = nil)
    return help(__method__) if options[:help]
    CliCfg.pp acct_request { |ua| ua.query(attributes, filter) }
  end

  desc "delete [username]", "delete user account"
  def delete(username = nil)
    return help(__method__) if options[:help]
    username ||= ask("User name")
    acct_request { |ua| ua.delete_by_name(username) }
  end

  desc "get [username]", "get user account information"
  def get(username = nil)
    return help(__method__) if options[:help]
    username ||= ask("User name")
    CliCfg.pp acct_request { |ua| ua.get_by_name(username) }
  end

  desc "password [username] [pwd]", "set password, alias 'pwd'"
  map "pwd" => "password"
  def password(username = nil, pwd = nil)
    return help(__method__) if options[:help]
    username, pwd = name_pwd(username, pwd)
    CliCfg.pp acct_request { |ua| ua.change_password_by_name(username, pwd) }
  end

  desc "userinfo", "get authenticated user information. alias 'info'"
  map "info" => "userinfo"
  def userinfo
    return help(__method__) if options[:help]
    CliCfg.pp id_request { |id| id.user_info }
  end

  desc "client_get [name]", "get client registration info. alias 'cg'"
  map "cg" => "client_get"
  def client_get(name)
    return help(__method__) if options[:help]
    CliCfg.pp client_reg_request { |cr| cr.get(name) }
  end

  no_tasks do

    def askd(prompt, defary)
      ask(prompt, default: (defary.join(' ') if defary && defary.respond_to?(:join)))
    end

    def client_info(defaults)
      scopes = askd("Supported scopes", defaults[:scope])
      resource_ids = askd("Authorized resource IDs", defaults[:resource_ids])
      grant_types = askd("Authorized grant types", defaults[:authorized_grant_types])
      roles = askd("Roles", defaults[:authorities])
      redir_uris = askd("Authorized redirection URIs", defaults[:redirect_uris])
      [scopes, resource_ids, grant_types, roles, redir_uris]
    end

  end

  desc "client_add [name]", "add client registration. alias 'ca'"
  method_option :clone, type: :string, aliases: "-c",
      desc: "get default client registration from existing client."
  method_option :secret, type: :string, aliases: "-s", desc: "set client secret"
  map "ca" => "client_add"
  def client_add(name = nil)
    return help(__method__) if options[:help]
    name ||= ask("New client name")
    secret = verified_pwd("New client secret", options['secret'])
    clone = options['clone']
    client_reg_request { |cr|
      defaults = clone ? cr.get(clone) : {}
      scopes, resource_ids, grant_types, roles, redir_uris = client_info(defaults)
      cr.create(name, secret, scopes, resource_ids, grant_types, roles, redir_uris)
    }
  end

  desc "client_update [name]", "update client registration info. alias 'cu'"
  method_option :secret, type: :string, aliases: "-s", lazy_default: "", desc: "update client secret, prompts if not given"
  map "cu" => "client_update"
  def client_update(name)
    return help(__method__) if options[:help]
    secret = verified_pwd("new client secret", secret == ""? nil: secret) if secret = options['secret']
    client_reg_request { |cr|
      defaults = cr.get(name)
      scopes, resource_ids, grant_types, roles, redir_uris = client_info(defaults)
      cr.update(name, secret, scopes, resource_ids, grant_types, roles, redir_uris)
    }
  end

  desc "client_delete [name]", "delete client registration info"
  def client_delete(name = nil)
    return help(__method__) if options[:help]
    name ||= ask("Client name")
    CliCfg.pp client_reg_request { |cr| cr.delete(name) }
  end
end

=begin

TODO:

  authcode [--scope]
    # create redir url,
    # how to authenticate user to uaa? call prompts and post?
    # get 302 back, parse query
    # get authcode

  update_user
  create, delete, update, list clients (compare uaa vs openid doc)
  manage authorizations

=end
