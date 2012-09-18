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
    @target, @auth_header = target, auth_header
  end

  # info is a hash structure converted to json and sent to the scim /Users endpoint
  def add_object(path, info)
    reply = json_parse_reply(*json_post(@target, path, info, @auth_header))
    return reply if reply[:id]
    raise BadResponse, "no id returned by create request to #{@target}#{path}"
  end

  # info is a hash structure converted to json and sent to the scim /Users endpoint
  def update_object(path, id, info)
    json_parse_reply(*json_put(@target, "#{path}/#{URI.encode(id)}", info,
        @auth_header, if_match: info[:meta][:version]))
  end

  # info is a hash structure converted to json and sent to the scim /Users endpoint
  def patch_object(path, id, info, attributes_to_delete = nil)
    info = info.merge(meta: { attributes: Util.arglist(attributes_to_delete) }) if attributes_to_delete
    json_parse_reply(*json_patch(@target, "#{path}/#{URI.encode(id)}", info, @auth_header))
  end

  def query_object(path, attributes = nil, filter = nil)
    query = {}
    query[:attributes] = Util.strlist(attributes, ",") if attributes
    query[:filter] = filter if filter
    json_get(@target, "#{path}?#{URI.encode_www_form(query)}", @auth_header)
  end

  def create(name, password, email_addresses = nil, given_name = name, family_name = name, groups = nil)
    logger.warn "#{self.class}##{__method__} is deprecated. Please use #{self.class}#add"
    info = {userName: name, password: password, name: {givenName: given_name, familyName: family_name}}
    info[:emails] = email_addresses.respond_to?(:each) ?
        email_addresses.each_with_object([]) { |email, o| o.unshift({:value => email}) } :
        [{:value => (email_addresses || name) }]
    info[:groups] = groups if groups
    add(info)
  end

  def add(info) add_object("/Users", info) end
  def update(user_id, info) update_object("/Users", user_id, info) end
  def patch(user_id, info, attributes_to_delete = nil) patch_object("/Users", user_id, info, attributes_to_delete) end
  def query(attributes = nil, filter = nil) query_object("/Users", attributes, filter) end
  def get(user_id) json_get(@target, "/Users/#{URI.encode(user_id)}", @auth_header) end
  def delete(user_id) http_delete @target, "/Users/#{URI.encode(user_id)}", @auth_header end
  def user_id_from_name(name) get_by_name(name)[:id] end
  def delete_by_name(name) delete user_id_from_name(name) end

  def change_password(user_id, new_password, old_password = nil)
    password_request = { password: new_password }
    password_request[:oldPassword] = old_password if old_password
    json_parse_reply(*json_put(@target, "/Users/#{URI.encode(user_id)}/password", password_request, @auth_header))
  end

  def query_by_value(attributes, filter_attribute, filter_value)
    query_object("/Users", attributes, "#{filter_attribute} eq \"#{filter_value}\"")
  end

  def change_password_by_name(name, new_password, old_password = nil)
    change_password(user_id_from_name(name), new_password, old_password)
  end

  def get_by_name(name)
    qinfo = query_by_value(nil, :username, name)
    unless qinfo && qinfo[:resources] && qinfo[:resources][0] && qinfo[:resources][0][:id]
      raise NotFound, "user #{name} not found in #{@target}"
    end
    # should be able to just return qinfo[:resources][0] here but uaa does not yet return all attributes for a query
    get qinfo[:resources][0][:id]
  end

  def members(group, *users)
    filter = users.each_with_object([]) { |u, o| o << "userName eq \"#{u}\" or id eq \"#{u}\"" }
    query_object("/Groups/#{group}/Users", "userName,id", filter.join(" or "))
  end

  def add_group(info) add_object("/Groups", info) end
  def update_group(id, info, attributes_to_delete = nil) update_object("/Groups", user_id, info, attributes_to_delete) end
  def query_groups(attributes = nil, filter = nil) query_object("/Groups", attributes, filter) end
  def get_group(id) json_get(@target, "/Groups/#{URI.encode(id)}", @auth_header) end
  def delete_group(id) http_delete @target, "/Groups/#{URI.encode(id)}", @auth_header end

end

end
