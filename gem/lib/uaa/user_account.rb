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

  private

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

  # supported query keys are: attributes, filter, startIndex, count
  # output hash keys are: resources, totalResults, itemsPerPage
  def query_objects(path, query)
    query = query.reject {|k, v| v.nil? }
    query[:attributes] = Util.strlist(Util.arglist(query[:attributes]), ",") if query[:attributes]
    qstr = query.empty?? "": "?#{URI.encode_www_form(query)}"
    unless (info = json_get(@target, "#{path}#{qstr}", @auth_header)).is_a?(Hash) && info[:resources].is_a?(Array)
      raise BadResponse, "invalid reply to query of #{@target}#{path}"
    end
    info
  end

  def get_object(path, id) json_get(@target, "#{path}/#{URI.encode(id)}", @auth_header) end
  def get_object_by_name(path, name_attr, name)
    info = query_objects(path, filter: "#{name_attr} eq \"#{name}\"")
    unless info && info[:resources] && info[:resources][0] && (id = info[:resources][0][:id])
      raise NotFound, "#{name} not found in #{@target}#{path}"
    end

    # TODO: should be able to just return info[:resources][0] here but uaa does not yet return all attributes for a query
    get_object(path, id)
  end

  def all_ids(method, users)
    filter = users.each_with_object([]) { |u, o| o << "userName eq \"#{u}\" or id eq \"#{u}\"" }
    all_pages(method, attributes: "userName,id", filter: filter.join(" or "))
  end

  public

  # the auth_header parameter refers to a string that can be used in an
  # authorization header. For oauth with jwt tokens this would be something
  # like "bearer xxxx.xxxx.xxxx". The Token class returned by TokenIssuer
  # provides an auth_header method for this purpose.
  def initialize(target, auth_header) @target, @auth_header = target, auth_header end

  def create(name, password, email_addresses = nil, given_name = name, family_name = name, groups = nil)
    logger.warn "#{self.class}##{__method__} is deprecated. Please use #{self.class}#add"
    info = {userName: name, password: password, name: {givenName: given_name, familyName: family_name}}
    info[:emails] = email_addresses.respond_to?(:each) ?
        email_addresses.each_with_object([]) { |email, o| o.unshift({:value => email}) } :
        [{:value => (email_addresses || name) }]
    info[:groups] = groups if groups
    add(info)
  end

  def query(attributes = nil, filter = nil)
    logger.warn "#{self.class}##{__method__} is deprecated. Please use #{self.class}#query_users"
    query = attributes ? {attributes: attributes}: {}
    query[:filter] = filter if filter
    query_objects("/Users", query)
  end

  def add(info) add_object("/Users", info) end
  def update(user_id, info) update_object("/Users", user_id, info) end
  def patch(user_id, info, attributes_to_delete = nil) patch_object("/Users", user_id, info, attributes_to_delete) end
  def query_users(query) query_objects("/Users", query) end
  def get(user_id) get_object("/Users", user_id) end
  def get_by_name(name) get_object_by_name("/Users", "username", name) end
  def user_id_from_name(name) get_by_name(name)[:id] end
  def delete(user_id) http_delete @target, "/Users/#{URI.encode(user_id)}", @auth_header end
  def delete_by_name(name) delete user_id_from_name(name) end
  def add_group(info) add_object("/Groups", info) end
  def update_group(id, info, attributes_to_delete = nil) update_object("/Groups", id, info) end
  def query_groups(query) query_objects("/Groups", query) end
  def get_group(id) json_get(@target, "/Groups/#{URI.encode(id)}", @auth_header) end
  def delete_group(id) http_delete @target, "/Groups/#{URI.encode(id)}", @auth_header end
  def get_group_by_name(name) get_object_by_name("/Groups", "displayname", name) end
  def group_id_from_name(name) get_group_by_name(name)[:id] end
  def query_ids(query) query_objects("/ids/Users", query) end

  def change_password(user_id, new_password, old_password = nil)
    password_request = { password: new_password }
    password_request[:oldPassword] = old_password if old_password
    json_parse_reply(*json_put(@target, "/Users/#{URI.encode(user_id)}/password", password_request, @auth_header))
  end

  def change_password_by_name(name, new_password, old_password = nil)
    change_password(user_id_from_name(name), new_password, old_password)
  end

  # collects all pages of entries from a query, returns array of results. Method can be
  # any method that takes a single query arg. currently :query_users and :query_groups
  def all_pages(method, query)
    query = query.reject {|k, v| v.nil? }
    query[:startIndex], info = 1, []
    while true
      qinfo = send(method, query)
      return info unless qinfo[:resources] && !qinfo[:resources].empty?
      info.concat(qinfo[:resources])
      return info unless qinfo[:totalResults] && qinfo[:totalResults] > info.length
      raise BadResponse, "incomplete pagination data from #{@target}#{path}" unless qinfo[:startIndex] && qinfo[:itemsPerPage]
      query[:startIndex] = info.length + 1
    end
  end

  def ids_exclusive(*users) all_ids(:query_ids, users) end
  def ids(*users) all_ids(:query_users, users) end

end

end
