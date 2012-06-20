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

require 'uaa'
require 'cli/stub_server'
require 'cli/base'

module CF::UAA

class StubUAA < Stub::Base

  class << self
    attr_accessor :reply_badly, :clients, :users
  end

  def inject_error
    case self.class.reply_badly
    when :non_json then reply.text("non-json reply")
    when :bad_json then reply.body = %<{"access_token":"good.access.token" "missed a comma":"there"}>
    end
  end

  def token(client, scope, user = nil)
    token_body = { jti: SecureRandom.uuid, aud: scope, scope: scope,
        client_id: client[:client_id]}
    token_body.merge!({email: user[:email], user_id: user[:id]}) if user
    TokenCoder.encode(token_body, nil, nil, 'none')
  end

  @clients =
  {
    "test_client" => { client_id: "test_client", secret: "test_secret",
      scope: ["read", "write", "test", "read-logs", "client_admin", "user_admin"],
      grants: ["client_credentials"] }
  }

  def find_client(basic_auth_header)
    ah = basic_auth_header.split(' ')
    self.class.clients.each { |k, v|
      return v if ah[1] == Base64::strict_encode64("#{v[:client_id]}:#{v[:secret]}")
    } if ah[0] =~ /^basic$/i
    nil
  end

  @users =
  [
    { id: 99, name: "joe+admin", password: "?joe's%password$@ ", email: "joe@email.com",
        scope: ["openid", "read_logs"] }
  ]

  def find_user(name, pwd = nil)
    i = self.class.users.index { |u| u[:name] == name && (!pwd || pwd == u[:password]) }
    self.class.users[i] if i
  end

  def valid_token(required_scope)
    return nil unless (ah = request.headers[:authorization]) && (ah = ah.split(' '))[0] =~ /^bearer$/i
    contents = TokenCoder.decode(ah[1])
    contents[:scope], required_scope = Util.arglist(contents[:scope]), Util.arglist(required_scope)
    return contents if required_scope.nil? || !(required_scope & contents[:scope]).empty?
    access_denied "not in scope"
    nil
  end

  def default_route; reply_in_kind({error: "not found", error_description: "unknown path #{request.path}"}, 404) end
  def bad_request(message = nil); reply_in_kind({error: "bad request#{message ? ',' : ''} #{message}"}, 400) end
  def oauth_error(err); reply.json({error: err}, 400) end
  def not_found; reply_in_kind({error: "not found"}, 404) end
  def access_denied(message = nil); reply_in_kind( {error: "access denied#{message ? ',' : ''} #{message}"}, 403) end

  route :get, '/' do
    reply_in_kind "welcome to stub UAA, version #{VERSION}"
  end

  route :get, '/oauth/clients' do
    return unless valid_token("client_read client_admin")
    reply_in_kind self.class.clients
  end

  route :post, '/oauth/clients' do
    return bad_request unless request.headers[:content_type] == "application/json"
    return unless valid_token("client_admin")
    reg = Util.json_parse(request.body)
    return bad_request("no client_id") unless id = reg[:client_id]
    return bad_request("client_id already exists") if self.class.clients.key?(id)
    self.class.clients[id] = reg
    reply.status = 201
  end

  route :put, %r{^/oauth/clients/([^/]+)$} do
    return bad_request unless request.headers[:content_type] == "application/json"
    return unless valid_token("client_admin")
    reg = Util.json_parse(request.body)
    return bad_request("no client_id") unless id = reg[:client_id]
    self.class.clients[id] = reg
    reply.status = 204
  end

  route :get, %r{^/oauth/clients/([^/]+)$} do
    return unless valid_token("client_read client_admin")
    return not_found unless client = self.class.clients[match[1]]
    reply_in_kind(client)
  end

  route :delete, %r{^/oauth/clients/([^/]+)$} do
  end

  route :get, "/oauth/clients/:client_id/tokens" do
  end

  route :delete, "/oauth/clients/:client_id/tokens/:token_id" do
  end

  route :put, "/oauth/clients/:client_id/password" do
  end

  route :get, '/login' do
    reply.json = {version: VERSION,
        prompts: { username: ["text", "Username"], password: ["password","Password"]}}
   end

  route :post, "/oauth/authorize" do
  end

  route :post, "/oauth/token", do
    unless request.headers[:accept] == "application/json" &&
        request.headers[:content_type] == "application/x-www-form-urlencoded"
      return reply_in_kind("bad request", 400)
    end
    unless client = find_client(request.headers[:authorization])
      reply.headers[:www_authenticate] = "basic"
      return reply.json({error: "invalid_client"}, 401)
    end
    params = TokenIssuer.decode_oauth_parameters(request.body)
    case params[:grant_type]
    when "authorization_code" then reply.status = 501 # should have params code, redirect_uri
    when "password"
      user = find_user(params[:username], params[:password])
      return reply.json({error: "invalid_grant"}, 400) unless user
      scope = Util.strlist(Util.arglist(params[:scope], user[:scope]) & user[:scope])
      return reply.json({error: "invalid_scope"}, 400) if scope.empty?
      reply.json(access_token: token(client, scope, user), token_type: "bearer",
          expires_in: 3600, scope: scope)
    when "client_credentials"
      scope = Util.strlist(Util.arglist(params[:scope], client[:scope]) & client[:scope])
      return reply.json({error: "invalid_scope"}, 400) if scope.empty?
      reply.json(access_token: token(client, scope), token_type: "bearer",
          expires_in: 3600, scope: scope)
    else
      reply.json({error: "unsupported_grant_type"}, 400)
    end
    inject_error
  end

  route :post, "/User" do
    return bad_request unless request.headers[:content_type] == "application/json"
    return unless valid_token("user_admin")
    acct = Util.json_parse(request.body)
    acct[:id] = SecureRandom.uuid
    #return bad_request("no username") unless name = reg[:username]
    #return bad_request("username already exists") if self.class.users.key?(name)
    self.class.users << acct
    reply.json(acct)
  end

  route :put, "/User/:user_id/password" do
  end

  route :get, "/Users" do
    # handle query: ?#{URI.encode_www_form(query)}", @auth_header)
  end

  route :get, "/User/:user_id" do
  end

  route :delete, "/User/:user_id" do
  end

  route :get, "/oauth/users/:user_id/tokens" do
  end

  route :delete, "/oauth/users/:user_id/tokens/:token_id" do
  end

  route :get, "/userinfo" do
  end

end

end
