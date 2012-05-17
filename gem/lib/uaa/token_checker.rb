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
  # * client_id - the id of the client or Resource Server (known to the
  # Authorization Server), used to authenticate with the /check_token endpoint
  #
  # * client_secret - the shared secret used to authenticate with
  # the /check_token endpoint.
  #
  # * audience_ids - an array or space separated strings and should
  # indicate values which indicate the token is intended for this service
  # instance. It will be compared with tokens as they are decoded to
  # ensure that the token was intended for this audience.
  def initialize(target, client_id, client_secret, audience_ids, debug = false)
    @target, @client_id, @client_secret = target, client_id, client_secret
    @audience_ids, @debug = Util.arglist(audience_ids), debug
  end

  # Returns hash of values from the Authorization Server that are associated
  # with the opaque token.
  def decode(auth_header)
    unless auth_header && (tkn = auth_header.split).length == 2
      raise AuthError, "invalid authentication header: #{auth_header}"
    end
    reply = json_get("/check_token?token_type=#{tkn[0]}&token=#{tkn[1]}", Http.basic_auth(@client_id, @client_secret))
    auds = Util.arglist(reply[:aud] || reply[:resource_ids])
    if @audience_ids && (!auds || (auds & @audience_ids).empty?)
      raise AuthError, "invalid audience: #{auds.join(' ')}"
    end
    reply
  end

  def validation_key
    status, body, headers = http_get("/token_key", "text/plain", Http.basic_auth(@resource_id, @secret))
    raise BadResponse, "#{@target} returned status #{status}" unless status == 200
    body
  end

end

end
