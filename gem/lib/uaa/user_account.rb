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

require 'base64'
require 'uaa/http'

# This class is for apps that need to manage User Accounts.
# It provides access to the SCIM endpoints on the UAA.
class Cloudfoundry::Uaa::UserAccount

  include Cloudfoundry::Uaa::Http

  class AuthError < RuntimeError; end

  attr_accessor :access_token

  def initialize(target, access_token)
    @target, @access_token = target, access_token
  end

  def create(username, password, email_addresses, other={})
    raise AuthError, "No token provided. You must login first and set the authorization token up." unless @access_token

    family_name = other[:family_name] if other[:family_name]
    given_name = other[:given_name] if other[:given_name]

    emails = []
    if email_addresses.respond_to?(:each)
      email_addresses.each do |email_address|
        emails.unshift({:value => email_address})
      end
    elsif !email_addresses.nil?
      emails = [{:value => email_addresses}]
    end

    if given_name.nil? && emails.size() > 0
      given_name = emails[0][:value]
    end

    if family_name.nil? && emails.size() > 0
      family_name = emails[0][:value]
    end
 
    request= {
      :name=>{
        :givenName=>given_name,
        :familyName=>family_name
      },
      :userName=>username,
      :emails=>emails
    }

    status, body, headers = http_post("/User", request.to_json, "application/json", "#{@access_token}")
    user = json_parse(body)
    if user[:error]
      raise BadResponse, "Error creating a user #{user.inspect}"
    end

    id = user[:id]
    password_request = {:password=>password}

    # TODO: rescue from 403 and ask user to reset password through
    # another channel
    status, body, headers = http_put("/User/#{id}/password", password_request.to_json, "application/json", "#{@access_token}")
    if status != 204
      raise BadResponse, "Error updating the user's password"
    end

    user
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
