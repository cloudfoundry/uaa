# This class is for resource servers

# Resource servers get tokens and need to validate and decode them, but they
# do not initiate their creation with the AS. The AcceptToken class is for
# this use. This may be the only class the cloud controller needs.

require 'uaa/http'
require 'uaa/error'
require 'jwt'
require 'base64'

class Cloudfoundry::Uaa::TokenDecoder

  include Cloudfoundry::Uaa::Http

  def initialize(target, resource_id, secret)
    @target, @resource_id, @secret = target, resource_id, secret
  end

  # returns hash of values from server that are associated with the opaque token
  def issuer_decode(auth_header)
    unless auth_header && (tkn = auth_header.split).length == 2
      raise AuthError, "invalid authentication header: #{auth_header}"
    end
    res_auth = "Basic " + Base64::strict_encode64("#{@resource_id}:#{@secret}")
    reply = json_get("/check_token?token_type=#{tkn[0]}&token=#{tkn[1]}", res_auth)
    return reply if reply[:resource_ids].include?(@resource_id)
    raise AuthError, "invalid resource audience: #{reply[:resource_ids]}"
  end

  # returns hash of values decoded from the token contents
  def decode(auth_header)
    unless auth_header && (tkn = auth_header.split).length == 2 && tkn[0] =~ /bearer/i
      raise AuthError, "invalid authentication header: #{auth_header}"
    end
    reply = JWT.decode(tkn[1], @secret)

    # TODO: the following line only symbolizes the top level hash keys, but rather
    # than introduce a large funciton to do it, we should get the JWT.decode call
    # to support the symbolize option to JSON.parse.
    reply = reply.each_with_object({}){|(k,v), h| h[k.to_sym] = v}

    return reply if reply[:resource_ids].include?(@resource_id)
    raise AuthError, "invalid resource audience: #{reply[:resource_ids]}"
  rescue JWT::DecodeError, NotImplementedError
    raise AuthError, "invalid authentication token"
  end

end
