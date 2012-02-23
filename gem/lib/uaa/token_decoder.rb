# This class is for resource servers

# Resource servers get tokens and need to validate and decode them, but they
# do not initiate their creation with the AS. This class it for resource
# servers which only accept Bearer JWT tokens and has the secret that can be
# used to verify the signature of the token.

require 'jwt'

class Cloudfoundry::Uaa::TokenDecoder

  include Cloudfoundry::Uaa::Http

  def initialize(resource_id, signing_secret)
    @resource_id, @secret = resource_id, signing_secret
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
