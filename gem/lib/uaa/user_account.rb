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

module CF::UAA

# This class is for apps that need to manage User Accounts.
# It provides access to the SCIM endpoints on the UAA.
class UserAccount

  include Http

  # the auth_header parameter refers to a string that can be used in an
  # authorization header. For oauth with jwt tokens this would be something
  # like "bearer xxxx.xxxx.xxxx". The Token class returned by TokenIssuer
  # provides an auth_header method for this purpose.
  def initialize(target, auth_header)
    unless target && auth_header
      raise AuthError, "No target and authorization provided. You must login first to get a token."
    end
    @target, @auth_header = target, auth_header
  end

  def create(name, password, email_addresses = nil, given_name = name, family_name = name, groups = nil)
    emails = []
    if email_addresses.respond_to?(:each)
      email_addresses.each { |email| emails.unshift({:value => email}) }
    else
      emails = [{:value => (email_addresses || name) }]
    end
    request = { userName: name, password: password, emails: emails,
        name: { givenName: given_name, familyName: family_name }}
    request[:groups] = Util.arglist(groups) if groups
    user = json_parse_reply(*json_post("/User", request, @auth_header))
    return user if user[:id]
    raise BadResponse, "no user id returned by create user: target #{@target}"
  end

  def change_password(user_id, new_password)
    password_request = { password: new_password }
    json_parse_reply(*json_put("/User/#{URI.encode(user_id)}/password", password_request, @auth_header))
  end

  def query(attributes = nil, filter = nil)
    query = {}
    query[:attributes] = attributes.respond_to?(:join) ? attributes.join(","): attributes.to_s if attributes
    query[:filter] = filter if filter
    json_get("/Users?#{URI.encode_www_form(query)}", @auth_header)
  end

  def query_by_value(attributes, filter_attribute, filter_value)
    query(attributes, %<#{filter_attribute} eq '#{filter_value}'>)
  end

  def get(user_id); json_get("/User/#{URI.encode(user_id)}", @auth_header) end
  def get_by_name(name); get user_id_from_name(name) end
  def delete(user_id); http_delete "/User/#{URI.encode(user_id)}", @auth_header end
  def delete_by_name(name); delete user_id_from_name(name) end

  def change_password_by_name(name, new_password)
    change_password(user_id_from_name(name), new_password)
  end

  def user_id_from_name(name)
    qinfo = query_by_value([:id, :active], :username, name)
    unless qinfo && qinfo[:resources] && qinfo[:resources][0] &&
        qinfo[:resources][0][:id] && qinfo[:resources][0][:active] == true
      raise NotFound, "user #{name} not found in #{@target}"
    end
    qinfo[:resources][0][:id]
  end

end

end
