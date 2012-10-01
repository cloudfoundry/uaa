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

# Web or Native Clients (in the OAuth2 sense) would use this class to get tokens
# that they can use to get access to resources

# Client Apps that want to get access on behalf of their users to
# resource servers need to get tokens via authcode and implicit flows,
# request scopes, etc., but they don't need to process tokens. This
# class is for these use cases.

require 'securerandom'
require 'uaa/http'

module CF::UAA

# info hash MUST include access_token, token_type and scope (if
# granted scope differs from requested scop). It should include expires_in.
# It may include refresh_token, scope, and other values from the auth server.
class Token
  attr_reader :info
  def initialize(info); @info = info end
  def auth_header; "#{info[:token_type]} #{info[:access_token]}" end
end

class TokenIssuer

  include Http
  attr_accessor :default_scope

  def initialize(target, client_id, client_secret = nil, default_scope = nil, token_target = nil)
    @target, @client_id, @client_secret = target, client_id, client_secret
    @default_scope = default_scope
    @token_target = token_target
  end

  # login prompts for use by app to collect credentials for implicit grant
  def prompts
    reply = json_get @target, '/login'
    return reply[:prompts] if reply && reply[:prompts]
    raise BadResponse, "No prompts in response from target #{@target}"
  end

  # gets an access token in a single call to the UAA with the client
  # credentials used for authentication. The credentials arg should
  # be an object such as a hash that will respond to a to_json method
  # to produce a json representation of the credential name/value pairs
  # as specified by the information retrieved by #prompts
  def implicit_grant_with_creds(credentials, scope = nil)
    # this manufactured redirect_uri is a convention here, not part of OAuth2
    redir_uri = "https://uaa.cloudfoundry.com/redirect/#{@client_id}"
    uri = authorize_path_args("token", redir_uri, scope, state = SecureRandom.uuid)

    # the accept header is only here so the uaa will issue error replies in json to aid debugging
    headers = {content_type: "application/x-www-form-urlencoded", accept: "application/json" }

     # required for current UAA implementation
    body = URI.encode_www_form(credentials: credentials.to_json)

    # TODO: the above can be changed to the following to be consistent with
    # the other OAuth APIs when CFID-239 is done:
    # body = URI.encode_www_form(credentials.merge(credentials: true))

    status, body, headers = request(@target, :post, uri, body, headers)
    raise BadResponse, "status #{status}" unless status == 302
    req_uri, reply_uri = URI.parse(redir_uri), URI.parse(headers[:location])
    fragment, reply_uri.fragment = reply_uri.fragment, nil
    return parse_implicit_params(fragment, state) if req_uri == reply_uri
    raise BadResponse, "bad location header"
  rescue URI::Error => e
    raise BadResponse, "bad location header in reply: #{e.message}"
  end

  # constructs a uri that the client is to return to the browser to direct
  # the user to the authorization server to get an authcode. The redirect_uri
  # is embedded in the returned uri so the authorization server can redirect
  # the user back to the client app.
  def implicit_uri(redirect_uri, scope = nil)
    @target + authorize_path_args("token", redirect_uri, scope)
  end

  def implicit_grant(implicit_uri, callback_query)
    in_params = Util.decode_form_to_hash(URI.parse(implicit_uri).query)
    unless in_params[:state] && in_params[:redirect_uri]
      raise ArgumentError, "redirect must happen before implicit grant"
    end
    parse_implicit_params callback_query, in_params[:state]
  end

  # constructs a uri that the client is to return to the browser to direct
  # the user to the authorization server to get an authcode. The redirect_uri
  # is embedded in the returned uri so the authorization server can redirect
  # the user back to the client app.
  def authcode_uri(redirect_uri, scope = nil)
    @target + authorize_path_args("code", redirect_uri, scope)
  end

  def authcode_grant(authcode_uri, callback_query)
    ac_params = Util.decode_form_to_hash(URI.parse(authcode_uri).query)
    unless ac_params[:state] && ac_params[:redirect_uri]
      raise ArgumentError, "authcode redirect must happen before authcode grant"
    end
    begin
      params = Util.decode_form_to_hash(callback_query)
      authcode = params[:code]
      raise BadResponse unless params[:state] == ac_params[:state] && authcode
    rescue URI::InvalidURIError, ArgumentError, BadResponse
      raise BadResponse, "received invalid response from target #{@target}"
    end
    request_token(grant_type: "authorization_code", code: authcode,
        redirect_uri: ac_params[:redirect_uri], scope: ac_params[:scope])
  end

  def owner_password_grant(username, password, scope = nil)
    request_token(grant_type: "password", username: username, password: password, scope: scope)
  end

  def client_credentials_grant(scope = nil)
    request_token(grant_type: "client_credentials", scope: scope)
  end

  def refresh_token_grant(refresh_token, scope = nil)
    request_token(grant_type: "refresh_token", refresh_token: refresh_token, scope: scope)
  end

  private

  def parse_implicit_params(encoded_params, state)
    params = Util.decode_form_to_hash(encoded_params)
    raise BadResponse, "mismatched state" unless state && params.delete(:state) == state
    raise TargetError.new(params), "error response from #{@target}" if params[:error]
    raise BadResponse, "no type and token" unless params[:token_type] && params[:access_token]
    Token.new params
  rescue URI::InvalidURIError, ArgumentError
    raise BadResponse, "received invalid response from target #{@target}"
  end

  # returns a CF::UAA::Token object which includes the access token and metadata.
  def request_token(params)
    if scope = Util.arglist(params[:scope], @default_scope)
      params[:scope] = scope.join(' ')
    else
      params.delete(:scope)
    end
    headers = {content_type: "application/x-www-form-urlencoded", accept: "application/json",
        authorization: Http.basic_auth(@client_id, @client_secret) }
    body = URI.encode_www_form(params)
    request_token_target = @token_target || @target
    reply = json_parse_reply(*request(request_token_target, :post, '/oauth/token', body, headers))
    raise BadResponse unless reply[:token_type] && reply[:access_token]
    Token.new reply
  end

  def authorize_path_args(response_type, redirect_uri, scope, state = SecureRandom.uuid)
    params = {client_id: @client_id, response_type: response_type, redirect_uri: redirect_uri, state: state}
    params[:scope] = scope = scope.join(' ') if scope = Util.arglist(scope, @default_scope)
    if scope && scope.include?("openid")
      params[:nonce] = state
      params[:response_type] = "#{response_type} id_token"
    end
    "/oauth/authorize?#{URI.encode_www_form(params)}"
  end

end

end
