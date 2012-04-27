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
require 'launchy'
require 'uaa'
require 'cli/stub_server'

module CF::UAA

class LoginCli < BaseCli

  desc "prompts", "show prompts for credentials required for implicit grant"
  map "p" => "prompts"
  def prompts
    return help(__method__) if options.help?
    Config.pp issuer_request(nil) { |ti| ti.prompts }
  end

  desc "client", "gets a token with client credentials grant"
  method_option :scope, type: :string, aliases: "-s", desc: "requested token scope"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret"
  map "c" => "client"
  def client
    return help(__method__) if options.help?
    Config.opts issuer_request { |ti| ti.client_credentials_grant.info }
  end

  desc "implicit [credentials]", "gets a token via implicit grant"
  method_option :scope, type: :string, aliases: "-s", desc: "requested token scope"
  map "i" => "implicit"
  def implicit(*args)
    return help(__method__) if options.help?
    Config.opts issuer_request("n/a") { |ti|
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
          err "Unknown prompt type \"#{v[0]}\" received from #{Config.target}"
        end
      end
      ti.implicit_grant(creds).info
    }
  end

  desc "owner_pwd [owner] [pwd]", "gets a token with an owner password grant."
  map "o" => "owner_password"
  method_option :scope, type: :string, aliases: "-s", desc: "requested token scope"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret"
  def owner_pwd(username = nil, pwd = nil)
    return help(__method__) if options[:help]
    username, pwd = name_pwd(username, pwd)
    Config.opts issuer_request { |ti| ti.owner_password_grant(username, pwd).info }
  end

  desc "refresh [refresh_token]", "gets a new access token from a refresh token"
  map "r" => "refresh"
  method_option :scope, type: :string, aliases: "-s", desc: "requested token scope"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret"
  def refresh(rtoken = Config.opts[:refresh_token])
    return help(__method__) if options[:help]
    Config.opts issuer_request { |ti| ti.refresh_token_grant(rtoken).info }
  end

  desc "authcode", "gets an access token using the authcode flow with browser"
  map "a" => "authcode"
  method_option :scope, type: :string, aliases: "-s", desc: "requested token scope"
  def authcode
    return help(__method__) if options[:help]
    tokn = nil
    issuer_request do |ti|
      uri = ti.authcode_uri("#{StubServer.url}/callback", scope)
      StubServer.responder do |request, reply|
        waiting_for_token = false
        reply.body = "got a reply"
        reply.headers[:content_type] = "text/plain"
        begin
          tokn = ti.authcode_grant(uri, URI.parse(request.path).query)
          reply.body = "you are now logged in and can close this window"
        rescue CF::UAA::TargetError => e
          reply.body = "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
        rescue Exception => e
          reply.body = "#{e.message}"
        ensure
          reply
        end
      end
      StubServer.thread_request do
        Launchy.open(uri, debug: true, dry_run: false)
        print "waiting for token "
        until tokn
          sleep 5
          print "."
        end
        puts "\nGot token:"
        Config.pp tokn.info
        Config.opts(user_token: tokn.info)
      end
    end
  end

  desc "token [token] [type]", "displays token contents as parsed locally or by the UAA"
  map "t" => "token"
  method_option :key, type: :string, aliases: "-k", desc: "token signing key"
  method_option :local, type: :string, aliases: "-l", desc: "parse token locally, validates if --key given"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret for remote token validation"
  def token(token = nil, token_type = nil)
    return help(__method__) if options[:help]
    token_type = "bearer" if token && !token_type
    token ||= Config.opts[:access_token]
    token_type ||= Config.opts[:token_type]
    return puts "no token to decode" unless token && token_type
    if options[:local]
      Config.pp CF::UAA::TokenCoder.decode(token, options[:key])
    else
      tkc = CF::UAA::TokenChecker.new(Config.target, Config.client_id, client_secret, trace?)
      Config.pp tkc.decode("#{Config.opts[:token_type]} #{Config.opts[:access_token]}")
    end
  rescue CF::UAA::TargetError => e
    puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    puts e.message, (e.backtrace if trace?)
  end

  private

  def client_secret
    options[:client_secret] || Config.opts[:client_secret] || ask("Client secret", echo: "*", forget: true)
  end

  def scope
    options[:scope] || Config.opts[:scope]
  end

  def issuer_request(csecret = client_secret)
    return yield CF::UAA::TokenIssuer.new(Config.target, Config.client_id, csecret, scope, trace?)
  rescue CF::UAA::TargetError => e
    puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    puts e.message, (e.backtrace if trace?)
  end

end

end
