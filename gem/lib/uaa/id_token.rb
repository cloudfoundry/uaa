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

class CF::UAA::IdToken

  include CF::UAA::Http

  def initialize(target)
    @target = target
  end

  def authen_info(id_token)
  # => {user_id, expires_on, auth_time, ...}
    reply = json_get("/check_id", "Bearer #{id_token}")

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

  def user_info(access_token)
  # => {user_id, name, email, verified, given_name, family_name, ... }
    reply = json_get("/userinfo?schema=openid", "Bearer #{access_token}")
  end

end
