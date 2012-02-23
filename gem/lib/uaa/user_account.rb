#-----------------------------------------------------------------------------
# This class is for apps that need to manage User Accounts.
# It provides access to the SCIM endpoints.

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
