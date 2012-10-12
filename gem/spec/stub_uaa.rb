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

  def inject_error(input = nil)
    case server.reply_badly
    when :non_json then reply.text("non-json reply")
    when :bad_json then reply.body = %<{"access_token":"good.access.token" "missed a comma":"there"}>
    when :bad_state then input[:state] = "badstate"
    when :no_token_type then input.delete(:token_type)
    end
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

  def ids_to_names(ids); ids ? ids.map { |id| server.scim.name(id) } : [] end
  def names_to_ids(names, rtype); names ? names.map { |name| server.scim.id(name, rtype) } : [] end
  def bad_request(message = nil); reply_in_kind(400, error: "bad request#{message ? ',' : ''} #{message}") end
  def not_found(name = nil); reply_in_kind(404, error: "#{name} not found") end

  def primary_email(emails)
    return unless emails
    emails.each {|e| return e[:value] if e[:type] && e[:type] == "primary"}
    emails[0][:value]
  end

  #----------------------------------------------------------------------------
  # miscellaneous endpoints
  #

  def default_route; reply_in_kind(404, error: "not found", error_description: "unknown path #{request.path}") end

  route :get, '/' do reply_in_kind "welcome to stub UAA, version #{VERSION}" end
  route :get, '/varz' do reply_in_kind(mem: 0, type: 'UAA', app: { version: VERSION } ) end
  route :get, '/token_key' do reply_in_kind(alg: "none", value: "none") end
  route :get, '/login' do reply_in_kind(server.info) end

  route :post, '/password/score', content_type: %r{application/x-www-form-urlencoded} do
    info = Util.decode_form_to_hash(request.body)
    return bad_request "no password to score" unless info[:password]
    score = info[:password].length > 10 || info[:password].length < 0 ? 10 : info[:password].length
    reply_in_kind(score: score, requiredScore: 0)
  end

  route :get, %r{^/userinfo(\?|$)(.*)} do
    return not_found unless (tokn = valid_token("openid")) &&
        (info = server.scim.get(tokn[:user_id], :user, :username, :id, :emails)) && info[:username]
    reply_in_kind(user_id: info[:id], user_name: info[:username], email: primary_email(info[:emails]))
  end

  #----------------------------------------------------------------------------
  # oauth2 endpoints and helpers
  #

  # current uaa token contents: exp, user_name, scope, email, user_id,
  #    client_id, client_authorities, user_authorities
  def token_reply_info(client, scope, user = nil, state = nil, refresh = false)
    interval = client[:access_token_validity] || 3600
    token_body = { jti: SecureRandom.uuid, aud: scope, scope: scope,
        client_id: client[:client_id], exp: interval + Time.now.to_i }
    if user
      token_body[:user_id] = user[:id]
      token_body[:email] = primary_email(user[:emails])
      token_body[:user_name] = user[:username]
    end
    info = { access_token: TokenCoder.encode(token_body, nil, nil, 'none'),
        token_type: "bearer", expires_in: interval, scope: scope}
    info[:state] = state if state
    info[:refresh_token] = "universal_refresh_token" if refresh
    inject_error(info)
    info
  end

  def auth_client(basic_auth_header)
    ah = basic_auth_header.split(' ')
    return unless ah[0] =~ /^basic$/i
    ah = Base64::strict_decode64(ah[1]).split(':')
    client = server.scim.get_by_name(ah[0], :client)
    client if client && client[:client_secret] == ah[1]
  end

  def find_user(name, pwd = nil)
    user = server.scim.get_by_name(name, :user, :password, :id, :emails, :username, :groups)
    user if user && (!pwd || user[:password] == pwd)
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

  def redir_with_query(cburi, params)
    reply.status = 302
    uri = URI.parse(cburi)
    uri.query = URI.encode_www_form(params)
    reply.headers[:location] = uri.to_s
  end

  def redir_err_f(cburi, state, msg); redir_with_fragment(cburi, error: msg, state: state) end
  def redir_err_q(cburi, state, msg); redir_with_query(cburi, error: msg, state: state) end

  # returns granted scopes
  # TODO: doesn't handle actual user authorization yet
  def calc_scope(client, user, requested_scope)
    possible_scope = ids_to_names(client[user ? :scope : :authorities])
    requested_scope = Util.arglist(requested_scope) || []
    return unless (requested_scope - possible_scope).empty?
    requested_scope = possible_scope if requested_scope.empty?
    granted_scopes = user ? (ids_to_names(user[:groups]) & requested_scope) : requested_scope # handle auto-deny
    Util.strlist(granted_scopes) unless granted_scopes.empty?
  end

  route [:post, :get], %r{^/oauth/authorize\?(.*)} do
    query = Util.decode_form_to_hash(match[1])
    client = server.scim.get_by_name(query[:client_id], :client)
    cburi, state = query[:redirect_uri], query[:state]

    # if invalid client_id or redir_uri: inform resource owner, do not redirect
    unless client && valid_redir_uri?(client, cburi)
      return bad_request "invalid client_id or redirect_uri"
    end
    if query[:response_type] == 'token'
      unless client[:authorized_grant_types].include?("implicit")
        return redir_err_f(cburi, state, "unauthorized_client")
      end
      if request.method == :post
        unless request.headers[:content_type] =~ %r{application/x-www-form-urlencoded} &&
            (creds = Util.decode_form_to_hash(request.body)) &&
            creds[:source] && creds[:source] == "credentials"
          return redir_err_f(cburi, state, "invalid_request")
        end
        unless user = find_user(creds[:username], creds[:password])
          return redir_err_f(cburi, state, "access_denied")
        end
      else
        return reply.status = 501 # TODO: how to authN user and ask for authorizations?
      end
      unless (granted_scope = calc_scope(client, user, query[:scope]))
        return redir_err_f(cburi, state, "invalid_scope")
      end
      # TODO: how to stub any remaining scopes that are not auto-approve?
      return redir_with_fragment(cburi, token_reply_info(client, granted_scope, user, query[:state]))
    end
    return redir_err_q(cburi, state, "invalid_request") unless request.method == :get
    return redir_err_q(cburi, state, "unsupported_response_type") unless query[:response_type] == 'code'
    unless client[:authorized_grant_types].include?("authorization_code")
      return redir_err_f(cburi, state, "unauthorized_client")
    end
    return reply.status = 501 unless query[:emphatic_user] # TODO: how to authN user and ask for authorizations?
    return redir_err_f(cburi, state, "access_denied") unless user = find_user(query[:emphatic_user])
    scope = calc_scope(client, user, query[:scope])
    redir_with_query(cburi, state: state, code: assign_auth_code(client[:id], user[:id], scope, cburi))
  end

  # if required and optional arrays are given, extra params are an error
  def bad_params?(params, required, optional = nil)
    required.each {|r|
      next if params[r]
      reply.json(400, error: "invalid_request", error_description: "no #{k} in request")
      return true
    }
    return false unless optional
    params.each {|k, v|
      next if required.include?(k) || optional.include?(k)
      reply.json(400, error: "invalid_request", error_description: "#{k} not allowed")
      return true
    }
    false
  end

  # TODO: need to save scope, timeout, client, redir_url, user_id, etc
  # when redeeming an authcode, code and redir_url must match
  @authcode_store = {}
  class << self; attr_accessor :authcode_store end
  def assign_auth_code(client_id, user_id, scope, redir_uri)
    code = SecureRandom.base64(8)
    raise "authcode collision" if self.class.authcode_store[code]
    self.class.authcode_store[code] = {client_id: client_id, user_id: user_id,
        scope: scope, redir_uri: redir_uri}
    code
  end
  def redeem_auth_code(client_id, redir_uri, code)
    return unless info = self.class.authcode_store.delete(code)
    return unless info[:client_id] == client_id && info[:redir_uri] == redir_uri
    [info[:user_id], info[:scope]]
  end

  route :post, "/oauth/token", content_type: %r{application/x-www-form-urlencoded},
        accept: %r{application/json} do
    unless client = auth_client(request.headers[:authorization])
      reply.headers[:www_authenticate] = "basic"
      return reply.json(401, error: "invalid_client")
    end
    return if bad_params?(params = Util.decode_form_to_hash(request.body), [:grant_type])
    unless client[:authorized_grant_types].include?(params[:grant_type])
      return reply.json(400, error: "unauthorized_client")
    end
    case params.delete(:grant_type)
    when "authorization_code"
       # TODO: need authcode store with requested scope, redir_uri must match
      return if bad_params?(params, [:code, :redirect_uri], [])
      user_id, scope = redeem_auth_code(client[:id], params[:redirect_uri], params[:code])
      return reply.json(400, error: "invalid_grant") unless user_id && scope
      user = server.scim.get(user, :user, :id, :emails, :username)
      reply.json(token_reply_info(client, scope, user, nil, true))
    when "password"
      return if bad_params?(params, [:username, :password], [:scope])
      user = find_user(params[:username], params[:password])
      return reply.json(400, error: "invalid_grant") unless user
      scope = calc_scope(client, user, params[:scope])
      return reply.json(400, error: "invalid_scope") unless scope
      reply.json(token_reply_info(client, scope, user))
    when "client_credentials"
      return if bad_params?(params, [], [:scope])
      scope = calc_scope(client, nil, params[:scope])
      return reply.json(400, error: "invalid_scope") unless scope
      reply.json(token_reply_info(client, scope))
    when "refresh_token"
      return if bad_params?(params, [:refresh_token], [:scope])
      return reply.json(400, error: "invalid_grant") unless params[:refresh_token] == "universal_refresh_token"
      # TODO: max scope should come from refresh token, or user from refresh token
      # this should use calc_scope when we know the user
      scope = ids_to_names(client[:scope])
      scope = Util.strlist(Util.arglist(params[:scope], scope) & scope)
      return reply.json(400, error: "invalid_scope") if scope.empty?
      reply.json(token_reply_info(client, scope))
    else
      reply.json(400, error: "unsupported_grant_type")
    end
    inject_error
  end

  route :post, "/alternate/oauth/token", content_type: %r{application/x-www-form-urlencoded},
        accept: %r{application/json} do
    request.path.replace("/oauth/token")
    server.info.delete(:token_endpoint) # this indicates this was executed for a unit test
    process
  end

  #----------------------------------------------------------------------------
  # client endpoints
  #
  def client_to_scim(info)
    [:authorities, :scope, :auto_approve_scope].each { |a| info[a] = names_to_ids(info[a], :group) if info.key?(a) }
    info
  end

  def scim_to_client(info)
    [:authorities, :scope, :auto_approve_scope].each { |a| info[a] = ids_to_names(info[a]) if info.key?(a) }
    info
  end

  route :get, '/oauth/clients' do
    return unless valid_token("clients.read")
    info, _ = server.scim.find(:client)
    reply_in_kind(info.each_with_object({}) { |c, o| o[c[:client_id]] = scim_to_client(c) })
  end

  route :post, '/oauth/clients', content_type: %r{application/json} do
    return unless valid_token("clients.write")
    server.scim.add(:client, client_to_scim(Util.json_parse(request.body, :downsym)))
    reply.status = 201
  end

  route :put, %r{^/oauth/clients/([^/]+)$}, content_type: %r{application/json} do
    return unless valid_token("clients.write")
    info = client_to_scim(Util.json_parse(request.body, :downsym))
    server.scim.update(server.scim.id(match[1], :client), info)
    reply.json(scim_to_client(info))
  end

  route :get, %r{^/oauth/clients/([^/]+)$} do
    return unless valid_token("clients.read")
    return not_found(match[1]) unless client = server.scim.get_by_name(match[1], :client, *StubScim::VISIBLE_ATTRS[:client])
    reply_in_kind(scim_to_client(client))
  end

  route :delete, %r{^/oauth/clients/([^/]+)$} do
    return unless valid_token("clients.write")
    return not_found(match[1]) unless server.scim.remove(server.scim.id(match[1], :client))
  end

  route :put, %r{^/oauth/clients/([^/]+)/secret$}, content_type: %r{application/json} do
    info = Util.json_parse(request.body, :downsym)
    if oldsecret = info[:oldsecret]
      return unless valid_token("clients.secret")
      return not_found(match[1]) unless client = server.scim.get(match[1], :client, :client_secret)
      return bad_request("old secret does not match") unless oldsecret == client[:client_secret]
    else
      return unless valid_token("uaa.admin")
    end
    return bad_request("no new secret given") unless info[:secret]
    server.scim.update(match[1], client_secret: info[:secret])
    reply.json(status: "ok", message: "secret updated")
  end

  #----------------------------------------------------------------------------
  # users and groups endpoints
  #
  route :post, %r{^/(Users|Groups)$}, content_type: %r{application/json} do
    return unless valid_token("scim.write")
    rtype = match[1] == "Users"? :user : :group
    id = server.scim.add(rtype, Util.json_parse(request.body, :downsym))
    server.auto_groups.each {|g| server.scim.add_member(g, id)} if rtype == :user && server.auto_groups
    reply_in_kind server.scim.get(id, rtype, *StubScim::VISIBLE_ATTRS[rtype])
  end

  route :put, %r{^/(Users|Groups)/([^/]+)$}, content_type: %r{application/json} do
    return unless valid_token("scim.write")
    rtype = match[1] == "Users"? :user : :group
    id = server.scim.update(match[2], Util.json_parse(request.body, :downsym), request.headers[:match_if], rtype)
    reply_in_kind server.scim.get(id, rtype, *StubScim::VISIBLE_ATTRS[rtype])
  end

  def sanitize_int(arg, default, min, max = nil)
    return default if arg.nil?
    return unless arg.to_i.to_s == arg && (i = arg.to_i) >= min
    max && i > max ? max : i
  end

  def page_query(rtype, query, attrs)
    if query[:attributes]
      attrs = attrs & Util.arglist(query[:attributes]).each_with_object([]) {|a, o| o << a.downcase.to_sym}
    end
    start, count = sanitize_int(query[:startindex], 1, 1), sanitize_int(query[:count], 15, 1, 3000)
    return bad_request("invalid startIndex or count") unless start && count
    info, total = server.scim.find(rtype, start - 1, count, query[:filter], attrs)
    reply_in_kind(resources: info, itemsPerPage: info.length, startIndex: start, totalResults: total)
  end

  route :get, %r{^/(Users|Groups)(\?|$)(.*)} do
    return unless valid_token("scim.read")
    rtype = match[1] == "Users"? :user : :group
    page_query(rtype, Util.decode_form_to_hash(match[3]), StubScim::VISIBLE_ATTRS[rtype])
  end

  route :get, %r{^/(Users|Groups)/([^/]+)$} do
    return unless valid_token("scim.read")
    rtype = match[1] == "Users"? :user : :group
    return not_found(match[2]) unless obj = server.scim.get(match[2], rtype, *StubScim::VISIBLE_ATTRS[rtype])
    reply_in_kind(obj)
  end

  route :delete, %r{^/(Users|Groups)/([^/]+)$} do
    return unless valid_token("scim.write")
    not_found(match[2]) unless server.scim.remove(match[2], match[1] == "Users"? :user : :group)
  end

  route :put, %r{^/Users/([^/]+)/password$}, content_type: %r{application/json} do
    info = Util.json_parse(request.body, :downsym)
    if oldpwd = info[:oldpassword]
      return unless valid_token("password.write")
      return not_found(match[1]) unless user = server.scim.get(match[1], :user, :password)
      return bad_request("old password does not match") unless oldpwd == user[:password]
    else
      return unless valid_token("scim.write")
    end
    return bad_request("no new password given") unless info[:password]
    server.scim.update(match[1], password: info[:password])
    reply.json(status: "ok", message: "password updated")
  end

  route :get, %r{^/ids/Users(\?|$)(.*)} do
    page_query(:user, Util.decode_form_to_hash(match[2]), [:username, :id])
  end

end

class StubUAA < Stub::Server

  attr_accessor :reply_badly
  attr_reader :scim, :auto_groups

  def initialize(boot_client = "admin", boot_secret = "adminsecret", logger = Util.default_logger)
    @scim = StubScim.new
    @auto_groups = ["password.write", "openid"]
        .each_with_object([]) { |g, o| o << @scim.add(:group, displayname: g) }
    ["scim.read", "scim.write", "uaa.resource"]
        .each { |g| @scim.add(:group, displayname: g) }
    gids = ["clients.write", "clients.read", "clients.secret", "uaa.admin"]
        .each_with_object([]) { |s, o| o << @scim.add(:group, displayname: s) }
    @scim.add(:client, client_id: boot_client, client_secret: boot_secret,
        authorized_grant_types: ["client_credentials"], authorities: gids,
        access_token_validity: 60 * 60 * 24 * 7)
    @scim.add(:client, {client_id: "vmc", authorized_grant_types: ["implicit"],
        scope: [@scim.id("openid", :group), @scim.id("password.write", :group)],
        access_token_validity: 5 * 60 })
    info = { commit_id: "not implemented",
        app: {name: "Stub UAA", version: VERSION, description: "User Account and Authentication Service, test server"},
        prompts: {username: ["text", "Username"], password: ["password","Password"]} }
    super(StubUAAConn, logger, info)
  end

end

end
