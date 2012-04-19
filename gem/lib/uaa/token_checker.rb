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

require 'base64'
require 'uaa/http'

# This class is for Resource Servers to decode an access token through
# an HTTP endpoint on the Authorization Server.

# Resource servers get tokens and need to validate and decode
# them. This class is for Resource Servers which can accept an opaque
# token from the Authorization Server and can make a call to the
# /check_token endpoint to validate the token.
class CF::UAA::TokenChecker

  include CF::UAA::Http

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
  def initialize(target, resource_id, secret, trace = false)
    @target, @resource_id, @secret, @trace = target, resource_id, secret, trace
  end

  # Returns hash of values from the Authorization Server that are associated
  # with the opaque token.
  def decode(auth_header)
    unless auth_header && (tkn = auth_header.split).length == 2
      raise CF::UAA::AuthError, "invalid authentication header: #{auth_header}"
    end
    res_auth = "Basic " + Base64::strict_encode64("#{@resource_id}:#{@secret}")
    reply = json_get("/check_token?token_type=#{tkn[0]}&token=#{tkn[1]}", res_auth)
    return reply if reply[:resource_ids].include?(@resource_id)
    raise CF::UAA::AuthError, "invalid resource audience: #{reply[:resource_ids]}"
  end

end
