# This class is for resource servers

# Resource servers get tokens and need to validate and decode them, but they
# do not initiate their creation with the AS. This class it for resource
# servers which only accept Bearer JWT tokens and has the secret that can be
# used to verify the signature of the token.

require 'uaa/error'
require 'uaa/jwt'

module Cloudfoundry::Uaa

  class TokenDecoder

    def initialize(resource_id, signing_secret)
      @resource_id, @secret = resource_id, signing_secret
    end

    # returns hash of values decoded from the token contents
    def decode(auth_header)
      unless auth_header && (tkn = auth_header.split).length == 2 && tkn[0] =~ /bearer/i
        raise AuthError, "invalid authentication header: #{auth_header}"
      end
      reply = JWT.decode(tkn[1], @secret)
      return reply if reply[:resource_ids].include?(@resource_id)
      raise AuthError, "invalid resource audience: #{reply[:resource_ids]}"
    rescue JWT::DecodeError
      raise AuthError, "invalid authentication token"
    end

  end

end
