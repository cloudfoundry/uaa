# This class is for Web Client Apps (in the OAuth2 sense) that want
# access to authenticated user information.  Basically this class is
# an OpenID Connect client.

class Cloudfoundry::Uaa::IdToken

  include Cloudfoundry::Uaa::Http

  def initialize(target, client_id, client_secret, scope)
  end

  def get_redirect_uri(callback_uri)
  # => uri string
  # save private @authcode_state, @authcode_callback_uri, @nonce
  end

  def get_token(callback_location_header)
  # use private @authcode_state, @authcode_callback_uri, @nonce
  # => token_type, token, id_token, expires_in, granted_scopes, others{}, refresh_token
  # => error_response
  end

  def authen_info
  # => {user_id, expires_on, auth_time, ...}
  end

  def user_info
  # => {user_id, name, email, verified, given_name, family_name, ... }
  end

end
