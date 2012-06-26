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
require 'stub_scim'

module CF::UAA

class StubUAAConn < Stub::Base

  def inject_error
    case server.reply_badly
    when :non_json then reply.text("non-json reply")
    when :bad_json then reply.body = %<{"access_token":"good.access.token" "missed a comma":"there"}>
    end
  end

  # current uaa token contents: exp, user_name, scope, email, user_id,
  #    client_id, client_authorities, user_authorities
  def token(client, scope, user = nil)
    token_body = { jti: SecureRandom.uuid, aud: scope, scope: scope,
        client_id: client[:display_name]}
    token_body.merge!({email: user[:email], user_id: user[:id]}) if user
    TokenCoder.encode(token_body, nil, nil, 'none')
  end

  def auth_client(basic_auth_header)
    ah = basic_auth_header.split(' ')
    return unless ah[0] =~ /^basic$/i
    ah = Base64::strict_decode64(ah[1]).split(':')
    client = server.scim.find_by_name(ah[0])
    client if client && client[:rtype] == :client && client[:password] == ah[1]
  end

  def find_user(name, pwd = nil)
    user = server.scim.find_by_name(name)
    user if user && user[:rtype] == :user && (!pwd || user[:password] == pwd)
  end

  def valid_token(required_scope)
    return nil unless (ah = request.headers[:authorization]) && (ah = ah.split(' '))[0] =~ /^bearer$/i
    contents = TokenCoder.decode(ah[1])
    contents[:scope], required_scope = Util.arglist(contents[:scope]), Util.arglist(required_scope)
    return contents if required_scope.nil? || !(required_scope & contents[:scope]).empty?
    access_denied "not in scope"
    nil
  end

  def ids_to_names(ids)
    ids.map { |id| server.scim.id_to_name(id) }
  end

  def names_to_ids(names)
    names.map { |name| server.scim.name_to_id(name) }
  end

  CLIENT_SCIM = [[:password, :client_secret], [:display_name, :client_id], [:groups, :scope]]
  def to_scim(attr_map, hsh)
    attr_map.each_with_object(hsh) { |m, h| h[m[0]] = h.delete(m[1]) if h.key?(m[1]) }
  end

  def from_scim(attr_map, hsh)
    attr_map.each_with_object(hsh) { |m, h| h[m[1]] = h.delete(m[0]) if h.key?(m[0]) }
  end

  def client_to_scim(reg)
    reg[:scope] = names_to_ids(reg[:scope]) if reg.key?(:scope)
    to_scim(CLIENT_SCIM, reg)
  end

  def scim_to_client(reg)
    reg[:groups] = ids_to_names(reg[:groups]) if reg.key?(:groups)
    from_scim(CLIENT_SCIM, reg)
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
    reply_in_kind server.scim.things(:client)
  end

  route :post, '/oauth/clients' do
    return bad_request unless request.headers[:content_type] == "application/json"
    return unless valid_token("client_admin")
    reg = client_to_scim(Util.json_parse(request.body))
    puts reg.inspect
    server.scim.add(:client, reg)
    reply.status = 201
  end

  route :put, %r{^/oauth/clients/([^/]+)$} do
    return bad_request unless request.headers[:content_type] == "application/json"
    return unless valid_token("client_admin")
    reg = client_to_scim(Util.json_parse(request.body))
    puts reg.inspect
    server.scim.update(match[1], reg)
    reply.status = 204
  end

  route :get, %r{^/oauth/clients/([^/]+)$} do
    return unless valid_token("client_read client_admin")
    return not_found unless client = server.scim.find_by_name(match[1])
    reply_in_kind(scim_to_client(client))
  end

  route :delete, %r{^/oauth/clients/([^/]+)$} do
  end

  route :get, "/oauth/clients/([^/]+)/tokens" do
  end

  route :delete, "/oauth/clients/([^/]+)/tokens/([^/]+):token_id" do
  end

  route :put, "/oauth/clients/([^/]+)/password" do
  end

  route :get, '/login' do
    reply.json = {version: VERSION,
        prompts: { username: ["text", "Username"], password: ["password","Password"]}}
   end

  # implicit grant returns: access_token, token_type, state, expires_in
  route :post, "/oauth/authorize" do
  end

  route :post, "/oauth/token", do
    unless request.headers[:accept] == "application/json" &&
        request.headers[:content_type] == "application/x-www-form-urlencoded"
      return reply_in_kind("bad request", 400)
    end
    unless client = auth_client(request.headers[:authorization])
      reply.headers[:www_authenticate] = "basic"
      return reply.json({error: "invalid_client"}, 401)
    end
    params = TokenIssuer.decode_oauth_parameters(request.body)
    case params[:grant_type]
    when "authorization_code" then reply.status = 501 # should have params code, redirect_uri
    when "password"
      user = find_user(params[:username], params[:password])
      return reply.json({error: "invalid_grant"}, 400) unless user
      scope = ids_to_names(user[:groups])
      scope = Util.strlist(Util.arglist(params[:scope], scope) & scope)
      return reply.json({error: "invalid_scope"}, 400) if scope.empty?
      reply.json(access_token: token(client, scope, user), token_type: "bearer",
          expires_in: 3600, scope: scope)
    when "client_credentials"
      scope = ids_to_names(client[:groups])
      scope = Util.strlist(Util.arglist(params[:scope], scope) & scope)
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
    user = server.scim.add(:user, Util.json_parse(request.body, :uncamel))
    reply.json(Util.hash_keys(user, :tocamel))
  end

  route :put, "/Users/([^/]+)/password" do
  end

  route :get, "/Users" do
    # handle query: ?#{URI.encode_www_form(query)}", @auth_header)
  end

  route :get, "/Users/([^/]+)" do
  end

  route :delete, "/Users/([^/]+)" do
  end

  route :get, "/oauth/users/([^/]+)/tokens" do
  end

  route :delete, "/oauth/users/([^/]+)/tokens/([^/]+)" do
  end

  # currently returns user_id, user_name, given_name, family_name, name, email
  route :get, "/userinfo" do
  end

end

class StubUAA < Stub::Server

  attr_accessor :reply_badly
  attr_reader :scim

  def initialize(debug = false)
    @scim = StubScim.new
    super(StubUAAConn, debug)
  end

end

end
