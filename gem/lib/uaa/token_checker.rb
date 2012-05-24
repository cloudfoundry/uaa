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

require 'uaa/http'

module CF::UAA

# This class is for Resource Servers to decode an access token through
# an HTTP endpoint on the Authorization Server.

# Resource servers get tokens and need to validate and decode
# them. This class is for Resource Servers which can accept an opaque
# token from the Authorization Server and can make a call to the
# /check_token endpoint to validate the token.
class TokenChecker

  include Http

  # Create a new instance of the token checker. Attributes:
  #
  # * target - the target base URL of the Authorization Server
  #
  # * resource_id - the id of the Resource Server (known to the
  # Authorization Server), used to validate the tokens and also
  # to authenticate with the /check_token endpoint
  #
  # * secret - the shared secret owned by the Resource Server and used
  # to authenticate with the /check_token endpoint.
  #
  def initialize(target, resource_id, secret, debug = false)
    @target, @resource_id, @secret, @debug = target, resource_id, secret, debug
  end

  # Returns hash of values from the Authorization Server that are associated
  # with the opaque token.
  def decode(auth_header)
    unless auth_header && (tkn = auth_header.split).length == 2
      raise AuthError, "invalid authentication header: #{auth_header}"
    end

    headers = {content_type: "application/x-www-form-urlencoded", accept: "application/json",
        authorization: Http.basic_auth(@resource_id, @secret) }
    body = URI.encode_www_form(token_type: tkn[0], token: tkn[1])
    reply = json_parse_reply(*request(:post, '/check_token', body, headers))
    #reply = json_get("/check_token?token_type=#{tkn[0]}&token=#{tkn[1]}", Http.basic_auth(@resource_id, @secret))
    return reply if reply[:resource_ids].include?(@resource_id)
    raise AuthError, "invalid resource audience: #{reply[:resource_ids]}"
  end

  def validation_key
    status, body, headers = http_get("/token_key", "text/plain", Http.basic_auth(@client_id, @client_secret))
    raise BadResponse, "#{@target} returned status #{status}" unless status == 200
    body
  	#TODO: in progress, when uaa switches to json output
  #def validation_key(auth_header)
    #body = json_get "/token_key", auth_header
    #raise BadResponse, "#{@target} returned status #{status}" unless status == 200
    #body
  end

end

end
