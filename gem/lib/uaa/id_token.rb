#
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
#

# This class is for Web Client Apps (in the OAuth2 sense) that want
# access to authenticated user information.  Basically this class is
# an OpenID Connect client.

require 'uaa/http'
require 'uaa/error'

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
