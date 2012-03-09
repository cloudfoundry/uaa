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

require 'uaa/http'

# This class is for apps that need to manage User Accounts.
# It provides access to the SCIM endpoints on the UAA.
class Cloudfoundry::Uaa::UserAccount

  include Cloudfoundry::Uaa::Http

  def initialize(target, authorization)
    @target, @authorization = target, authorization
  end

  def create(username, password, email_addresses = nil, given_name = username, family_name = username)
    unless @authorization
      raise AuthError, "No authorization provided. You must login first to get a token."
    end

    emails = []
    if email_addresses.respond_to?(:each)
      email_addresses.each { |email| emails.unshift({:value => email}) }
    else
      emails = [{:value => (email_addresses || username) }]
    end

    request = { userName: username, emails: emails,
        name: { givenName: given_name, familyName: family_name }}
    user = json_parse_reply(*http_post("/User", request.to_json, "application/json", @authorization))
    unless user[:id]
      raise BadResponse, "no user id returned for new user from target #{@target}"
    end

    # TODO: change this when CFID-184 is done (include password in create user call)
    begin
      change_password user[:id], password
    rescue BadResponse
      # give it a good try to delete the user since we couldn't set the password,
      # then reraise the original exception
      begin
        delete user[:id]
      rescue
      end
      raise
    end
    user

  end

  def update(user_id, info = {})
  # => yes/no, error
  end

  def change_password(user_id, new_password)
    password_request = { password: new_password }
    status, body, headers = http_put("/User/#{user_id}/password", password_request.to_json, "application/json", @authorization)
    unless status == 204
      raise BadResponse, "Error updating the user's password from target #{@target}, status #{status}"
    end
  end

  def query(attribute, filter_attribute, filter_value)
    query = { attributes: attribute, filter: "#{filter_attribute} eq #{filter_value}" }
    json_get("/Users?#{URI.encode_www_form(query)}", @authorization)
  end

  def delete(user_id)
    unless (status = http_delete("/User/#{user_id}", @authorization)) == 200
      raise (status == 404 ? NotFound : BadResponse), "invalid response from #{@target}: #{status}"
    end
  end

end
