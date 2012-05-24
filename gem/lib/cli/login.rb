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
  namespace :login
  def self.banner(task, namespace = true, subcommand = true)
    "#{basename} #{task.formatted_usage(self, true, subcommand)}"
  end

  class_option :scope, type: :string, aliases: "-s", desc: "requested token scope"

  desc "prompts", "show prompts for credentials required for implicit grant"
  map "p" => "prompts"
  def prompts
    return help(__method__) if help?
    pp issuer_request(nil) { |ti| ti.prompts }
  end

  desc "client", "gets a token with client credentials grant"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret"
  map "c" => "client"
  def client
    return help(__method__) if help?
    Config.opts token: issuer_request { |ti| ti.client_credentials_grant.info }
  end

  desc "implicit [credentials]", "gets a token via implicit grant"
  map "i" => "implicit"
  def implicit(*args)
    return help(__method__) if help?
    Config.opts token: issuer_request("n/a") { |ti|
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
          err "Unknown prompt type \"#{v[0]}\" received from #{cur_target_url}"
        end
      end
      ti.implicit_grant_with_creds(creds).info
    }
  end

  desc "owner_pwd [owner] [pwd]", "gets a token with an owner password grant."
  map "o" => "owner_password"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret"
  def owner_pwd(username = nil, pwd = nil)
    return help(__method__) if help?
    username, pwd = name_pwd(username, pwd)
    Config.opts token: issuer_request { |ti| ti.owner_password_grant(username, pwd).info }
  end

  desc "refresh [refresh_token]", "gets a new access token from a refresh token"
  map "r" => "refresh"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret"
  def refresh(rtoken = Config.opts[:refresh_token])
    return help(__method__) if help?
    Config.opts token: issuer_request { |ti| ti.refresh_token_grant(rtoken).info }
  end

  desc "authcode", "gets a token using the authcode flow with browser"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret"
  map "a" => "authcode"
  def authcode
    return help(__method__) if help?
    tokn = nil
    issuer_request do |ti|
      uri = ti.authcode_uri("#{StubServer.url}/callback", scope)
      StubServer.responder do |request, reply|
        reply.headers[:content_type] = "text/plain"
        begin
          tokn = ti.authcode_grant(uri, URI.parse(request.path).query)
          reply.body = "you are now logged in and can close this window"
        rescue TargetError => e
          reply.body = "#{e.message}:\r\n#{JSON.pretty_generate(e.info)}\r\n#{e.backtrace if trace?}"
        rescue Exception => e
          reply.body = "#{e.message}\r\n#{e.backtrace if trace?}"
        end
        reply
      end
      StubServer.thread_request do
        Launchy.open(uri, debug: true, dry_run: false)
        print "waiting for token "
        until tokn
          sleep 5
          print "."
        end
        puts "\nGot token:"
        pp tokn.info
        Config.opts token: tokn.info
      end
    end
  end

  desc "browser", "gets a token using the implicit flow with browser"
  map "b" => "browser"
  def browser
    return help(__method__) if help?
    script_page = <<-HTML.gsub(/^ +/, '')
      <html><body><script type="text/javascript">
      var fragment = location.hash.substring(1);
      var req = new XMLHttpRequest();
      //document.write(fragment + "<br><br>");
      req.open('POST', "/callback", false);
      req.setRequestHeader("Content-type","application/x-www-form-urlencoded");
      req.send(fragment);
      document.write(req.responseText);
      </script></body></html>
    HTML
    tokn = nil
    issuer_request(nil) do |ti|
      uri = ti.implicit_uri("#{StubServer.url}/callback", scope)
      StubServer.responder do |request, reply|
        return reply.status = 404 unless request.path == "/callback"
        begin
          reply.headers[:content_type] = "text/plain"
          if request.method == :post
            tokn = ti.implicit_grant(uri, request.body)
            reply.body = "Successfully retrieved token, you are logged in"
          else
            reply.headers[:content_type] = "text/html"
            reply.body = script_page
          end
        rescue Exception => e
          reply.status = 400
          reply.body = "#{e.message}:\r\n#{JSON.pretty_generate(e.info)}\r\n#{e.backtrace if trace?}"
        end
        reply
      end
      StubServer.thread_request do
        Launchy.open(uri, debug: true, dry_run: false)
        print "waiting for token "
        until tokn
          sleep 5
          print "."
        end
        puts "\nsuccessfully logged in"
        #pp tokn.info
        Config.opts token: tokn.info
      end
    end
    rescue Exception => e
      puts "unhandled exception #{e}"
  end

  desc "token [token] [type]", "displays token contents as parsed locally or by the UAA"
  map "t" => "token"
  method_option :key, type: :string, aliases: "-k", desc: "token signing key"
  method_option :local, type: :string, aliases: "-l", desc: "parse token locally, validates if --key given"
  method_option :client_secret, type: :string, aliases: "-c", desc: "registered client secret for remote token validation"
  def token(token = nil, token_type = nil)
    return help(__method__) if help?
    token_type = "bearer" if token && !token_type
    token_info = Config.opts[:token] || {}
    token ||= token_info[:access_token]
    token_type ||= token_info[:token_type]
    return puts "no token to decode" unless token && token_type
    if opts[:local]
      Util.pp TokenCoder.decode(token, opts[:key])
    else
      tkc = TokenChecker.new(cur_target_url, cur_client_id, client_secret, trace?)
      pp tkc.decode("#{token_type} #{token}")
    end
  rescue TargetError => e
    puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    puts e.message, (e.backtrace if trace?)
  end

  desc "key", "get the UAA's token signing key(s)"
  map "k" => "key"
  def key
    return help(__method__) if help?
    tkc = TokenChecker.new(cur_target_url, cur_client_id, nil, nil, trace?)
    pp tkc.validation_key auth_header
  rescue TargetError => e
    puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    puts e.message, (e.backtrace if trace?)
  end

  private

  def client_secret
    opts[:client_secret] || Config.opts[:client_secret] || ask("Client secret", echo: "*", forget: true)
  end

  def scope
    opts[:scope] || Config.opts[:scope]
  end

  def issuer_request(csecret = client_secret)
    return yield TokenIssuer.new(cur_target_url, cur_client_id, csecret, scope, trace?)
  rescue TargetError => e
    puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    puts e.message, (e.backtrace if trace?)
  end

end

end
