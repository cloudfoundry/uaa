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

require 'base64'
require 'securerandom'
require 'uaa/http'

class CF::UAA::Token

  # info hash MUST include access_token, token_type and scope (if
  # granted scope differs from requested scop). It should include expires_in.
  # It may include refresh_token, scope, and other values from the auth server.
  attr_reader :info

  def initialize(info)
    @info = info
  end

  def auth_header
    "#{info[:token_type]} #{info[:access_token]}"
  end
end

class CF::UAA::TokenIssuer

  include CF::UAA::Http

  def initialize(target, client_id, client_secret, scope, resource_ids)
    @target, @client_id, @client_secret = target, client_id, client_secret
    @scope, @resource_ids = scope, resource_ids
  end

  # login prompts for use by app to collect credentials for implicit grant
  def prompts
    reply = json_get '/login'
    return reply[:prompts] if reply && reply[:prompts]
    raise CF::UAA::BadResponse, "No prompts in response from target #{@target}"
  end

  # credentials should be an object such as a hash that will respond to a
  # to_json method to product a json representation of the credential
  # name/value pairs retrieved by #prompts
  def implicit_grant(credentials)
    # this manufactured redirect_uri is a convention here, not part of OAuth2
    redirect_uri = "http://uaa.cloudfoundry.com/redirect/#{@client_id}"
    state = SecureRandom.uuid
    params = {client_id: @client_id, response_type: "token", scope: @scope,
        redirect_uri: redirect_uri, state: state}
    uri = "/oauth/authorize?#{URI.encode_www_form(params)}"
    headers = {content_type: "application/x-www-form-urlencoded"}
    body = URI.encode_www_form(credentials: credentials.to_json)
    status, body, headers = request(:post, uri, body, headers)
    begin
      raise CF::UAA::BadResponse unless status == 302
      loc = headers[:location].split('#')
      raise CF::UAA::BadResponse unless loc.length == 2 && URI.parse(loc[0]) == URI.parse(redirect_uri)
      reply = self.class.decode_oauth_parameters(loc[1])
      raise CF::UAA::BadResponse unless reply[:state] == state && reply[:token_type] && reply[:access_token]
    rescue URI::InvalidURIError, ArgumentError, CF::UAA::BadResponse
      raise CF::UAA::BadResponse, "received invalid response from target #{@target}"
    end
    CF::UAA::Token.new reply
  end

  # constructs a uri that the client is to return to the browser to direct
  # the user to the authorization server to get an authcode. The redirect_uri
  # is embedded in the returned authcode_uri so the authorization server can
  # redirect the user back to the client app.
  def authcode_uri(redirect_uri)
    params = {client_id: @client_id, response_type: "code", scope: @scope,
        redirect_uri: redirect_uri, state: SecureRandom.uuid}
    "#{@target}/oauth/authorize?#{URI.encode_www_form(params)}"
  end

  def authcode_grant(authcode_uri, callback_query)
    begin
      ac_params = self.class.decode_oauth_parameters(URI.parse(authcode_uri).query)
      unless ac_params[:state] && ac_params[:redirect_uri]
        raise ArgumentError, "authcode redirect must happen before authcode grant"
      end
      params = self.class.decode_oauth_parameters(callback_query)
      authcode = params[:code]
      raise CF::UAA::BadResponse unless params[:state] == ac_params[:state] && authcode
    rescue URI::InvalidURIError, ArgumentError, CF::UAA::BadResponse
      raise CF::UAA::BadResponse, "received invalid response from target #{@target}"
    end
    request_token(grant_type: "authorization_code", code: authcode,
        redirect_uri: ac_params[:redirect_uri])
  end

  def owner_password_grant(username, password)
    request_token(grant_type: "password", username: username, password: password)
  end

  def client_credentials_grant
    request_token(grant_type: "client_credentials")
  end

  def refresh_token_grant(refresh_token = info[:refresh_token])
    request_token(grant_type: "refresh_token", refresh_token: refresh_token)
  end

  private

  # returns a string suitable for use in an authorization header in a
  # request to a resource server. Specific values from the authorization
  # server included with the token can be retrieved from the info method.
  def request_token(params)
    headers = {'Content-Type'=> "application/x-www-form-urlencoded",
        'Accept'=>"application/json",
        'Authorization' => self.class.client_auth_header(@client_id, @client_secret) }
    body = URI.encode_www_form(params.merge(scope: @scope))
    reply = json_parse_reply(*request(:post, '/oauth/token', body, headers))
    raise CF::UAA::BadResponse unless reply[:token_type] && reply[:access_token]
    CF::UAA::Token.new reply
  end

  # Takes an x-www-form-urlencoded string and returns a hash of symbol => value.
  # It raises an ArgumentError if a key occurs more than once, which is a
  # restriction of OAuth query strings. See draft-ietf-oauth-v2-23 section 3.1.
  def self.decode_oauth_parameters(url_encoded_pairs)
    args = {}
    URI.decode_www_form(url_encoded_pairs).each do |p|
      k = p[0].to_sym
      raise ArgumentError, "duplicate keys in oauth form parameters" if args[k]
      args[k] = p[1]
    end
    args
  end

  def self.client_auth_header(id, secret)
    "Basic " + Base64::strict_encode64("#{id}:#{secret}")
  end

end
