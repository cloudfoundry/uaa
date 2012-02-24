# This class is for resource servers

# Resource servers get tokens and need to validate and decode them, but they
# do not initiate their creation with the AS. This is for
# this use. It is for resource servers which can accept an opaque token
# from the uaa and can make a call to the check_token endpoint to validate
# the token.

require 'uaa/http'
require 'uaa/error'
require 'base64'

module Cloudfoundry::Uaa

class TokenChecker

  include Http

  def initialize(target, resource_id, secret)
    @target, @resource_id, @secret = target, resource_id, secret
  end

  # returns hash of values from server that are associated with the opaque token
  def decode(auth_header)
    unless auth_header && (tkn = auth_header.split).length == 2
      raise AuthError, "invalid authentication header: #{auth_header}"
    end
    res_auth = "Basic " + Base64::strict_encode64("#{@resource_id}:#{@secret}")
    reply = json_get("/check_token?token_type=#{tkn[0]}&token=#{tkn[1]}", res_auth)
    return reply if reply[:resource_ids].include?(@resource_id)
    raise AuthError, "invalid resource audience: #{reply[:resource_ids]}"
  end

end

end
