# This class is for resource servers

# Resource servers get tokens and need to validate and decode them, but they
# do not initiate their creation with the AS. The AcceptToken class is for
# this use. This may be the only class the cloud controller needs.

class Cloudfoundry::Uaa::TokenDecoder

  include Cloudfoundry::Uaa::Http

  def initialize(target, resource_id, secret)
    @target, @resource_id, @secret = target, resource_id, secret
  end

  # returns hash of decoded values or parsed error from server
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
