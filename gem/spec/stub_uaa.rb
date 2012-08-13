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
require 'stub_scim'
require 'pp'

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
  def token_reply_info(client, scope, user = nil, state = nil)
    interval = client[:access_token_validity] || 3600
    token_body = { jti: SecureRandom.uuid, aud: scope, scope: scope,
        client_id: client[:displayname], exp: interval + Time.now.to_i }
    token_body[:user_id] = user[:id] if user
    token_body[:email] = user[:emails][0][:value] if user && user[:emails]
    token_body[:user_name] = user[:username] if user && user[:username]
    info = { access_token: TokenCoder.encode(token_body, nil, nil, 'none'),
        token_type: "bearer", expires_in: interval, scope: scope}
    info[:state] = state if state
    info
  end

  def auth_client(basic_auth_header)
    ah = basic_auth_header.split(' ')
    return unless ah[0] =~ /^basic$/i
    ah = Base64::strict_decode64(ah[1]).split(':')
    client = server.scim.get_by_name(ah[0], :client)
    client if client && client[:password] == ah[1]
  end

  def find_user(name, pwd = nil)
    user = server.scim.get_by_name(name, :user)
    user if user && (!pwd || user[:password] == pwd)
  end

  def valid_token(required_scope)
    return nil unless (ah = request.headers[:authorization]) && (ah = ah.split(' '))[0] =~ /^bearer$/i
    contents = TokenCoder.decode(ah[1])
    contents[:scope], required_scope = Util.arglist(contents[:scope]), Util.arglist(required_scope)
    return contents if required_scope.nil? || !(required_scope & contents[:scope]).empty?
    reply_in_kind(403, error: "insufficient_scope",
        error_description: "required scope #{Util.strlist(required_scope)}")
    nil
  end

  def valid_redir_uri?(client, redir_uri)
    t = URI.parse(redir_uri)
    return true unless (ruris = client[:redirect_uris]) && !ruris.empty?
    false unless ruris.each { |reg_uri|
      r = URI.parse(reg_uri)
      return true if r.scheme == t.scheme && r.host == t.host &&
          (!r.port || r.port == t.port) && (!r.path || r.path == t.path)
    }
  end

  def redir_with_fragment(cburi, params)
    reply.status = 302
    uri = URI.parse(cburi)
    uri.fragment = URI.encode_www_form(params)
    reply.headers[:location] = uri.to_s
  end

  def ids_to_names(ids); ids.map { |id| server.scim.name(id) } end
  def names_to_ids(names, rtype); names.map { |name| server.scim.id(name, rtype) } end

  CLIENT_SCIM = [[:password, :client_secret], [:displayname, :client_id],
    [:groups, :authorities]]
  def to_scim(attr_map, hsh)
    attr_map.each_with_object(hsh) { |m, h| h[m[0]] = h.delete(m[1]) if h.key?(m[1]) }
  end

  def from_scim(attr_map, hsh)
    attr_map.each_with_object(hsh) { |m, h| h[m[1]] = h.delete(m[0]) if h.key?(m[0]) }
  end

  def client_to_scim(reg)
    reg[:authorities] = names_to_ids(reg[:authorities], :group) if reg.key?(:authorities)
    to_scim(CLIENT_SCIM, reg)
  end

  def scim_to_client(reg)
    reg[:groups] = ids_to_names(reg[:groups]) if reg.key?(:groups)
    from_scim(CLIENT_SCIM, reg)
  end

  def default_route; reply_in_kind(404, error: "not found", error_description: "unknown path #{request.path}") end
  def bad_request(message = nil); reply_in_kind(400, error: "bad request#{message ? ',' : ''} #{message}") end
  def oauth_error(err); reply.json(400, error: err) end
  def not_found(name = nil); reply_in_kind(404, error: "#{name} not found") end

  route :get, '/' do
    reply_in_kind "welcome to stub UAA, version #{VERSION}"
  end

  route :get, '/oauth/clients' do
    return unless valid_token("clients.read")
    reply_in_kind server.scim.find(:client).each_with_object({}) { |id, o|
      info = scim_to_client(server.scim.get(id))
      o[info[:client_id]] = info
    }
  end

  route :post, '/oauth/clients' do
    return bad_request unless request.headers[:content_type] == "application/json"
    return unless valid_token("clients.write")
    server.scim.add(:client, client_to_scim(Util.json_parse(request.body)))
    reply.status = 201
  end

  route :put, %r{^/oauth/clients/([^/]+)$} do
    return bad_request unless request.headers[:content_type] == "application/json"
    return unless valid_token("clients.write")
    info = client_to_scim(Util.json_parse(request.body))
    server.scim.update(server.scim.id(match[1], :client), info)
    reply.status = 204
  end

  route :get, %r{^/oauth/clients/([^/]+)$} do
    return unless valid_token("clients.read")
    return not_found(match[1]) unless client = server.scim.get_by_name(match[1], :client)
    reply_in_kind(scim_to_client(client))
  end

  route :delete, %r{^/oauth/clients/([^/]+)$} do
    return unless valid_token("clients.write")
    return not_found(match[1]) unless server.scim.remove(server.scim.id(match[1], :client))
    reply.status = 204
  end

  route :put, %r{^/oauth/clients/([^/]+)/secret$} do
  end

  route :get, '/login' do
    reply.json(version: VERSION,
        prompts: { username: ["text", "Username"], password: ["password","Password"]})
  end

  route :get, '/varz' do
    reply.json(mem: 0, type: 'UAA', app: { version: VERSION } )
  end

  route :get, '/token_key' do
    reply.json(alg: "none", value: "none")
  end

  route :post, '/password/score' do
    unless request.headers[:content_type] == "application/x-www-form-urlencoded"
      return bad_request "invalid content type"
    end
    info = Util.decode_form_to_hash(request.body)
    return bad_request "no password to score" unless info[:password]
    score = info[:password].length > 10 || info[:password].length < 0 ? 10 : info[:password].length
    reply.json(score: score, requiredscore: 0)
  end

  # implicit grant returns: access_token, token_type, state, expires_in
  route :post, %r{^/oauth/authorize\?(.*)$} do
    unless request.headers[:content_type] == "application/x-www-form-urlencoded"
      return bad_request "invalid content type"
    end
    query = Util.decode_form_to_hash(match[1])
    client = server.scim.get_by_name(query[:client_id], :client)
    cburi = query[:redirect_uri]

    # if invalid client_id or redir_uri: inform resource owner, do not redirect
    unless client && valid_redir_uri?(client, cburi)
      return bad_request "invalid client_id or redirect_uri"
    end
    unless client[:authorized_grant_types].include? "implicit"
      return redir_with_fragment(cburi, error: "unauthorized_client", state: query[:state])
    end
    unless query[:response_type] == 'token'
      return redir_with_fragment(cburi, error: "unsupported_response_type", state: query[:state])
    end
    creds = Util.json_parse(Util.decode_form_to_hash(request.body)[:credentials])
    unless user = find_user(creds[:username], creds[:password])
      return redir_with_fragment(cburi, error: "access_denied", state: query[:state])
    end
    possible_scope = ids_to_names(client[:scope])
    requested_scope = query[:scope] ? Util.arglist(query[:scope]) : possible_scope
    granted_scope = ids_to_names(user[:groups]) & requested_scope # handle auto-deny
    if granted_scope.empty? || !(requested_scope - possible_scope).empty?
      return redir_with_fragment(cburi, error: "invalid_scope", state: query[:state])
    end
    # TODO: how to stub any remaining scopes that are not auto-approve?
    granted_scope = Util.strlist(granted_scope)
    redir_with_fragment(cburi, token_reply_info(client, granted_scope, user, query[:state]))
  end

  route :post, "/oauth/token", do
    unless request.headers[:accept] == "application/json" &&
        request.headers[:content_type] == "application/x-www-form-urlencoded"
      return reply_in_kind(400, "bad request")
    end
    unless client = auth_client(request.headers[:authorization])
      reply.headers[:www_authenticate] = "basic"
      return reply.json(401, error: "invalid_client")
    end
    params = Util.decode_form_to_hash(request.body)
    case params[:grant_type]
    when "authorization_code" then reply.status = 501 # should have params code, redirect_uri
    when "password"
      user = find_user(params[:username], params[:password])
      return reply.json(400, error: "invalid_grant") unless user
      scope = ids_to_names(user[:groups])
      scope = Util.strlist(Util.arglist(params[:scope], scope) & scope)
      return reply.json(400, error: "invalid_scope") if scope.empty?
      reply.json(token_reply_info(client, scope, user))
    when "client_credentials"
      scope = ids_to_names(client[:groups])
      scope = Util.strlist(Util.arglist(params[:scope], scope) & scope)
      return reply.json(400, error: "invalid_scope") if scope.empty?
      reply.json(token_reply_info(client, scope))
    else
      reply.json(400, error: "unsupported_grant_type")
    end
    inject_error
  end

  def clean_user(user)
    return unless user
    user.delete(:password)
    user.delete(:rtype)
    user
  end

  route :post, "/User" do
    return bad_request unless request.headers[:content_type] == "application/json"
    return unless valid_token("scim.write")
    info, id = Util.json_parse(request.body).merge!(active: true), nil
    info[:groups] ||= []
    ["openid", "password.write"].each { |gn|
      id = server.scim.id(gn, :group)
      info[:groups] << id unless info[:groups].include?(id)
    }
    user = clean_user(server.scim.get(server.scim.add(:user, info)))
    reply.json(Util.hash_keys(user, :tostr))
  end

  route :put, %r{^/User/([^/]+)/password$} do
    return bad_request unless request.headers[:content_type] == "application/json"
    info = Util.json_parse(request.body)
    oldpwd = info[:oldpassword]
    if oldpwd
      return unless valid_token("password.write")
      return not_found(match[1]) unless user = server.scim.get(match[1], :user)
      return bad_request("old password does not match") unless oldpwd == user[:password]
    else
      return unless valid_token("scim.write")
    end
    return bad_request("no new password given") unless info[:password]
    server.scim.update(match[1], password: info[:password])
    reply.status = 204
  end

  route :get, %r{^/Users\?(.*)$} do
    return bad_request unless request.headers[:content_type] == "application/json"
    return unless valid_token("scim.read")
    query, name = Util.decode_form_to_hash(match[1]), nil
    if !query || !query[:filter]
      users = server.scim.find(:user).each_with_object([]) { |id, o|
        o << clean_user(server.scim.get(id))
      }
    elsif !(m = /username eq '([^']+)'/.match(query[:filter]))
      return bad_request("only filter of the form \"username eq 'joe'\" is implemented")
    else
      users = [clean_user(server.scim.get_by_name(name = m[1], :user))]
    end
    return not_found(name) if users.empty?
    reply.json(resources: Util.hash_keys(users, :tostr))
  end

  route :get, %r{^/User/([^/]+)$} do
    return bad_request unless request.headers[:content_type] == "application/json"
    return unless valid_token("scim.read")
    return not_found(match[1]) unless user = server.scim.get(match[1], :user)
    reply.json Util.hash_keys(clean_user(user), :tostr)
  end

  route :delete, %r{^/User/([^/]+)$} do
    return unless valid_token("scim.write")
    return not_found(match[1]) unless server.scim.remove(match[1], :user)
  end

  route :get, %r{^/userinfo\??(.*)$} do
    return not_found unless (tokn = valid_token("openid")) &&
        (info = server.scim.get(tokn[:user_id])) && info[:username]
    info[:user_name] = info.delete(:username)
    reply.json(info)
  end

end

class StubUAA < Stub::Server

  attr_accessor :reply_badly
  attr_reader :scim

  def initialize(boot_client = "admin", boot_secret = "adminsecret", logger = Util.default_logger)
    @scim = StubScim.new
    ["scim.read", "scim.write", "password.write", "openid", "uaa.resource"]
        .each { |g| @scim.add(:group, displayname: g) }
    gids = ["clients.write", "clients.read", "clients.secret", "uaa.admin"]
        .each_with_object([]) { |s, o| o << @scim.add(:group, displayname: s) }
    @scim.add(:client, displayname: boot_client, password: boot_secret,
        authorized_grant_types: ["client_credentials"], groups: gids,
        access_token_validity: 60 * 60 * 24 * 7)
    @scim.add(:client, {displayname: "vmc", authorized_grant_types: ["implicit"],
        scope: [@scim.id("openid", :group), @scim.id("password.write", :group)],
        access_token_validity: 5 * 60 })
    super(StubUAAConn, logger)
  end

end

end
