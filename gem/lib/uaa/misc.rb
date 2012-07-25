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

# This class is for Web Client Apps (in the OAuth2 sense) that want
# access to authenticated user information.  Basically this class is
# an OpenID Connect client.

require 'uaa/http'

module CF::UAA

# everything is miscellaneous
#
# this class provides interfaces to UAA endpoints that are not in the context
# of an overall class of operations, like "user accounts" or "tokens". It's
# also for some apis like "change user password" or "change client secret" that
# use different forms of authentication than other operations on those types
# of resources.
class Misc

  class << self
    include Http
  end

  def self.check_id(target, token)
    @target = target
    reply = json_get("/check_id", "Bearer #{token}")

  # To verify the validity of the Token response, the Client MUST do the following:

  # - Check that the OP that responded was really the intended OP.
  # - The Client MUST validate that the client_id in the aud (audience) Claim
  #   is one it has registered for the Issuer identified by the value in the
  #   iss (issuer) Claim. The ID Token MUST be rejected if the value of aud
  #   (audience) is not valid for the Issuer.
  # - The value of the iss (issuer) Claim must match the Issuer for the
  #   Check ID Endpoint
  # - The current time MUST be less than the value of the exp Claim.
  # - The value of the nonce Claim MUST be checked to verify that it is the
  #   same value as the one that was sent in the Authorization Request. The
  #   Client SHOULD check the nonce value for replay attacks. The precise
  #   method for detecting replay attacks is Client specific.
  # - If the acr Claim was requested, the Client SHOULD check that the asserted
  #   Claim Value is appropriate. The meaning and processing of acr Claim
  #   Values is out of scope for this specification.
  # - If the auth_time Claim was requested, the Client SHOULD check the value
  #   and request re-authentication if it determines too much time has elapsed
  #   since the last user authentication.
  # - The Check ID Endpoint has not returned an error for the ID Token being
  #   expired or invalid.
  # - Check that the iss (issuer) is equal to that of the pre-configured or
  #   discovered Issuer Identifier for the user session.
  # - The iat Claim may be used by the client to reject tokens that were issued
  #   too far away from the current time, limiting the amount of time that
  #   nonces must be stored to prevent attacks. The acceptable range is Client
  #   specific.
    reply
  end

  def self.whoami(target, auth_header)
    @target = target
    json_get("/userinfo?schema=openid", auth_header)
  end

  def self.server(target)
    @target = target
    reply = json_get '/login'
    return reply if reply && reply[:prompts]
    raise BadResponse, "Invalid response from target #{target}"
  end

  def self.validation_key(target, client_id = nil, client_secret = nil)
    @target = target
    json_get("/token_key", (client_id ? Http.basic_auth(client_id, client_secret) : nil))
  end

  # Returns hash of values from the Authorization Server that are associated
  # with the opaque token.
  def self.decode_token(target, client_id, client_secret, token, token_type = "bearer", audience_ids = nil)
    @target = target
    reply = json_get("/check_token?token_type=#{token_type}&token=#{token}", Http.basic_auth(client_id, client_secret))
    auds = Util.arglist(reply[:aud] || reply[:resource_ids])
    if audience_ids && (!auds || (auds & audience_ids).empty?)
      raise AuthError, "invalid audience: #{auds.join(' ')}"
    end
    reply
  end

  # this is an unauthenticated request so a client can change their secret if
  # they have the current secret.
  def self.change_secret(target, client_id, old_secret, new_secret)
    req = { oldSecret: old_secret, secret: new_secret }
    json_parse_reply(*json_put("/oauth/clients/#{client_id}/password", req))
  end

  # this is an unauthenticated request so a user can change their password if
  # they have the current password.
  def self.change_password(user_id, old_password, new_password)
    req = { password: new_password, oldPassword: old_password }
    json_parse_reply(*json_put("/User/#{URI.encode(user_id)}/password", req))
  end

end

end
