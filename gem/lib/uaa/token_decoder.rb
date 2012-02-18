# This class is for resource servers

# Resource servers get tokens and need to validate and decode them, but they
# do not initiate their creation with the AS. The AcceptToken class is for
# this use. This may be the only class the cloud controller needs.

class Cloudfoundry::Uaa::TokenDecoder

  include Cloudfoundry::Uaa::Http

  attr_reader :issuer, :res_id, :res_secret

  def initialize(issuer, res_id, res_secret)
  end

  def decode(auth_header)
  # reply with hash of decoded values or parsed error from server
  end

end
