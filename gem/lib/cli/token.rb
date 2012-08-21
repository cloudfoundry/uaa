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
require 'launchy'
require 'uaa'
require 'cli/stub_server'

module CF::UAA

class TokenCatcher < Stub::Base

  def process_grant(data)
    server.logger.debug "processing grant for path #{request.path}"
    secret = server.info.delete(:client_secret)
    ti = TokenIssuer.new(Config.target, server.info.delete(:client_id), secret)
    tkn = secret ? ti.authcode_grant(server.info.delete(:uri), data) :
        ti.implicit_grant(server.info.delete(:uri), data)
    server.info.update(tkn.info)
    reply.text "you are now logged in and can close this window"
  rescue TargetError => e
    reply.text "#{e.message}:\r\n#{JSON.pretty_generate(e.info)}\r\n#{e.backtrace}"
  rescue Exception => e
    reply.text "#{e.message}\r\n#{e.backtrace}"
  ensure
    server.logger.debug "reply: #{reply.body}"
  end

  route(:get, '/favicon.ico') { reply.headers[:content_type] = "image/vnd.microsoft.icon"
    reply.body = File.read File.expand_path File.join __FILE__, '..', 'favicon.ico' }
  route(:get, %r{^/authcode\?(.*)$}) { process_grant match[1] }
  route(:post, '/callback') { process_grant request.body }
  route :get, '/callback' do
    server.logger.debug "caught redirect back from UAA after authentication"
    reply.headers[:content_type] = "text/html"
    reply.body = <<-HTML.gsub(/^ +/, '')
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
  end
end

class TokenCli < CommonCli

  topic "Tokens"

  define_option :client, "--client <name>", "-c"
  define_option :scope, "--scope <list>"
  desc "token get [credentials...]",
      "Gets a token by posting user credentials with an implicit grant request",
      [:client, :scope] do |*args|
    client_name = opts[:client] || "vmc"
    token = issuer_request(client_name, "") { |ti|
      prompts = ti.prompts
      creds = {}
      prompts.each do |k, v|
        if arg = args.shift
          creds[k] = arg
        elsif v[0] == "text"
          creds[k] = ask(v[1])
        elsif v[0] == "password"
          creds[k] = ask_pwd v[1]
        else
          raise "Unknown prompt type \"#{v[0]}\" received from #{Context.target}"
        end
      end
      ti.implicit_grant_with_creds(creds, opts[:scope]).info
    }
    return say "attempt to get token failed", "" unless token && token[:access_token]
    tokinfo = TokenCoder.decode(token[:access_token], nil, nil, false)
    Config.context = tokinfo[:user_name]
    Config.add_opts(user_id: tokinfo[:user_id])
    Config.add_opts token
    say_success "implicit (with posted credentials) "
  end

  define_option :secret, "--secret <secret>", "-s", "client secret"
  desc "token client get [name]",
      "Gets a token with client credentials grant", [:secret, :scope] do |id|
    id = clientname(id)
    return unless info = issuer_request(id, clientsecret) { |ti|
      ti.client_credentials_grant(opts[:scope]).info
    }
    Config.context = id
    Config.add_opts info
    say_success "client credentials"
  end

  define_option :password, "-p", "--password <password>", "user password"
  desc "token owner get [client] [user]", "Gets a token with a resource owner password grant",
      [:secret, :password, :scope] do |client, user|
    return unless info = issuer_request(clientname(client), clientsecret) { |ti|
        ti.owner_password_grant(user = username(user), userpwd, opts[:scope]).info
    }
    Config.context = user
    Config.add_opts info
    say_success "owner password"
  end

  desc "token refresh [refreshtoken]", "Gets a new access token from a refresh token", [:client, :secret, :scope] do |rtok|
    rtok ||= Config.value(:refresh_token)
    Config.add_opts issuer_request(clientname, clientsecret) { |ti| ti.refresh_token_grant(rtok, opts[:scope]).info }
    say_success "refresh"
  end

  VMC_TOKEN_FILE = File.join ENV["HOME"], ".vmc_token"

  def use_browser(client_id, secret = nil)
    catcher = Stub::Server.new(TokenCatcher,
        Util.default_logger(debug? ? :debug : trace? ? :trace : :info),
        client_id: client_id, client_secret: secret).run_on_thread
    uri = issuer_request(client_id, secret) { |ti|
      secret ? ti.authcode_uri("#{catcher.url}/authcode", opts[:scope]) :
          ti.implicit_uri("#{catcher.url}/callback", opts[:scope])
    }
    return unless catcher.info[:uri] = uri
    say "launching browser with #{uri}" if trace?
    Launchy.open(uri, debug: true, dry_run: false)
    print "waiting for token "
    while catcher.info[:uri] || !catcher.info[:access_token]
      sleep 5
      print "."
    end
    Config.context = TokenCoder.decode(catcher.info[:access_token], nil, nil, false)[:user_name]
    Config.add_opts catcher.info
    say_success secret ? "authorization code" : "implicit"
    return unless opts[:vmc]
    begin
      tok_json = File.open(VMC_TOKEN_FILE, 'r') { |f| f.read } if File.exists?(VMC_TOKEN_FILE)
      vmc_tokens = Util.json_parse(tok_json, :none) || {}
      vmc_tokens[Config.target.to_s.gsub("://uaa.", "://api.")] = auth_header
      File.open(VMC_TOKEN_FILE, 'w') { |f| f.write(vmc_tokens.to_json) }
    rescue Exception => e
      say "", "Unable to save token to vmc token file", "#{e.class}: #{e.message}", (e.backtrace if trace?)
    end
  end

  define_option :vmc, "--[no-]vmc", "save token in the ~/.vmc_tokens file"
  desc "token authcode get", "Gets a token using the authcode flow with browser",
      [:client, :secret, :scope, :vmc] { use_browser(clientname, clientsecret) }

  desc "token implicit get", "Gets a token using the implicit flow with browser",
      [:client, :scope, :vmc] { use_browser opts[:client] || "vmc" }

  define_option :key, "--key <key>", "Token validation key"
  desc "token decode [token] [tokentype]",
      "Show token contents as parsed locally or by the UAA. Decodes locally unless --client and --secret are given. Validates locally if --key given",
      [:key, :client, :secret] do |token, ttype|
    ttype = "bearer" if token && !ttype
    token ||= Config.value(:access_token)
    ttype ||= Config.value(:token_type)
    return say "no token to decode" unless token && ttype
    handle_request do
      if opts[:client] && opts[:secret]
        pp Misc.decode_token(Config.target, opts[:client], opts[:secret], token, ttype)
      else
        info = TokenCoder.decode(token, opts[:key], opts[:key], !!opts[:key])
        say info.inspect if trace?
        pp info
        say "", "Note: no key given to validate token signature", "" unless opts[:key]
      end
    end
  end

  define_option :all, "--[no-]all", "-a", "remove all contexts"
  desc "token delete [contexts...]",
      "Delete current or specified context tokens and settings", [:all] do |*args|
    begin
      return Config.delete if opts[:all]
      return args.each { |arg| Config.delete(Config.target, arg.to_i.to_s == arg ? arg.to_i : arg) } unless args.empty?
      return Config.delete(Config.target, Config.context) if Config.context
      say "no target set, no contexts given -- nothing to delete"
    rescue Exception => e
      say "", "#{e.class}: #{e.message}", (e.backtrace if trace?), ""
    end
  end

  private

  def say_success(grant)
    say "", "Successfully fetched token via a #{grant} grant.",
        "Target: #{Config.target}", "Context: #{Config.context}", ""
  end

  def issuer_request(client_id, secret = nil)
    return yield TokenIssuer.new(Config.target.to_s, client_id, secret)
  rescue TargetError => e
    say "\n#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    say "\n#{e.class}: #{e.message}", (e.backtrace if trace?)
  end

end

end
