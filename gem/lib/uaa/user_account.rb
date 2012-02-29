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

# This class is for apps that need to manage User Accounts.
# It provides access to the SCIM endpoints.

require 'base64'
require 'uaa/http'

class Cloudfoundry::Uaa::UserAccount

  include Cloudfoundry::Uaa::Http

  def initialize(issuer, client_id, client_secret)
  end

  def create(username, password, email, other)
  # => user_id
  end

  def update(user_id, info = {})
  # => yes/no, error
  end

  def change_password(user_id, old_password, new_password)
  # => yes/no, error
  end

  def query(attr_name, attr_value)
  # => user_ids[], or users{}?
  end

  def delete(user_id)
  # => yes/no, error
  end

end
