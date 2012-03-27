#--
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
#++

require 'uaa/http'

# This class is for apps that need to manage User Accounts.
# It provides access to the SCIM endpoints on the UAA.
class Cloudfoundry::Uaa::UserAccount

  include Cloudfoundry::Uaa::Http

  # the authorization parameter refers to a string that can be used in an
  # authorization header. For oauth with jwt tokens this would be something
  # like "bearer xxxx.xxxx.xxxx". The TokenIssuer methods return a string
  # in the expected form.
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

    request = { userName: username, password: password, emails: emails,
        name: { givenName: given_name, familyName: family_name }}
    user = json_parse_reply(*http_post("/User", request.to_json,
        "application/json", @authorization))
    return user if user[:id]
    raise BadResponse, "no user id returned by create user: target #{@target}"
  end

  def change_password(user_id, new_password)
    password_request = { password: new_password }
    status, body, headers = http_put("/User/#{user_id}/password",
        password_request.to_json, "application/json", @authorization)
    return true if status == 204
    raise BadResponse, "Change password error: target #{@target}, status #{status}"
  end

  def query_by_value(attribute, filter_attribute, filter_value)
    query = { attributes: attribute, filter: "#{filter_attribute} eq '#{filter_value}'" }
    json_get("/Users?#{URI.encode_www_form(query)}", @authorization)
  end

  def get(user_id)
    json_get("/User/#{URI.encode(user_id)}", @authorization)
  end

  def list
    json_get("/Users?attributes=userName", @authorization)
  end

  def delete(user_id)
    unless (status = http_delete("/User/#{user_id}", @authorization)) == 200
      raise (status == 404 ? NotFound : BadResponse), "invalid response from #{@target}: #{status}"
    end
  end

  def delete_by_name(username)
    delete user_id_from_name(username)
  end

  def change_password_by_name(username, new_password)
    change_password(user_id_from_name(username), new_password)
  end

  private

  def user_id_from_name(name)
    qinfo = query_by_value(:id, :username, name)
    unless qinfo && qinfo[:resources] && qinfo[:resources][0] && qinfo[:resources][0][:id]
      raise NotFound, "user #{name} not found in #{@target}"
    end
    qinfo[:resources][0][:id]
  end

end
