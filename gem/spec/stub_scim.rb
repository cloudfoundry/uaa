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

require 'uaa/util'

module CF::UAA

class SchemaViolation < RuntimeError; end
class AlreadyExists < RuntimeError; end

class StubScim

  COMMON_ATTRS = [:externalid, :displayname, :groups]
  BOOLEANS = [:active]
  NUMBERS = [:access_token_validity, :refresh_token_validity]
  GROUPS = [:groups, :auto_approved_scopes, :scope]
  REFERENCES = [:members, :owners, :readers]
  ENUMS = { authorized_grant_types: ["client_credentials", "implicit",
      "authorization_code", "password", "refresh_token"] }
  COMMON_SUB_ATTRS = [:value, :display, :primary, :type]
  NAME_SUB_ATTRS = [ :formatted, :familyname, :givenname, :middlename,
      :honorificprefix, :honorificsuffix ]
  ADDR_SUB_ATTRS = [ :formatted, :streetaddress, :locality, :region,
      :postal_code, :country, :primary, :type ]
  AUTHZ_SUB_ATTRS = [ :client_id, :group, :exp ]
  META_SUB_ATTRS = [:created, :lastmodified, :location, :version]
  GENERAL_MULTI = [:emails, :phonenumbers, :ims, :photos, :entitlements,
      :roles, :x509certificates]
  NAME_ATTR = { user: :username, client: :displayname, group: :displayname }
  LEGAL_ATTRS = {
      user: COMMON_ATTRS + [:username, :nickname,
        :profileurl, :title, :usertype, :preferredlanguage, :locale,
        :timezone, :active, :password, :emails, :phonenumbers, :ims, :photos,
        :entitlements, :roles, :x509_certificates, :name, :addresses,
        :authorizations],
      client: COMMON_ATTRS + [:password, :authorized_grant_types,
        :scope, :auto_approved_scopes, :access_token_validity,
        :refresh_token_validity, :redirect_uris],
      group: COMMON_ATTRS + [:members, :owners, :readers] }

  def initialize
    @things = []
  end

  def valid_complex?(value, subattrs, simple_ok = false)
    return true if simple_ok && value.is_a?(String)
    return unless value.is_a?(Hash) && (!simple_ok || value.key?(:value))
    value.each { |k, v| return unless subattrs.include?(k) }
  end

  def valid_multi?(values, subattrs, simple_ok = false)
    return unless values.is_a?(Array)
    values.each { |value| return unless valid_complex?(value, subattrs, simple_ok) }
  end

  def valid_id?(id, rtype)
    @things.index { |thing| (!rtype || thing[:rtype] == rtype) && thing[:id] == id }
  end

  def valid_ids?(value, rtype = nil)
    return unless value.is_a?(Array)
    value.each do |ref|
      return unless ref.is_a?(String) && valid_id?(ref, rtype) ||
          ref.is_a?(Hash) && ref.key?(:value) && valid_id?(ref[:value], rtype)
    end
  end

  def valid?(rtype, thing)
    thing.each do |k, v|
      raise SchemaViolation, "illegal #{k} on #{rtype}" unless LEGAL_ATTRS[rtype].include?(k)
      valid_attr = case k
        when *BOOLEANS then v == !!v
        when *NUMBERS then v.is_a?(Integer)
        when *GENERAL_MULTI then valid_multi?(v, COMMON_SUB_ATTRS, true)
        when *GROUPS then valid_ids?(v, :group)
        when *REFERENCES then valid_ids?(v)
        when ENUMS[k] then ENUMS[k].include?(v)
        when :name then valid_complex?(v, NAME_SUB_ATTRS)
        when :addresses then valid_multi?(v, ADDR_SUB_ATTRS)
        when :authorizations then valid_multi?(v, AUTHZ_SUB_ATTRS)
        else true # must ba a string, no checking yet
      end
      raise SchemaViolation, "#{v} is an invalid #{k}" unless valid_attr
    end
  end

  def add(rtype, stuff)
    raise SchemaViolation, "new #{rtype} has no name #{NAME_ATTR[rtype]}" unless stuff.is_a?(Hash) && (name = stuff[NAME_ATTR[rtype]])
    raise AlreadyExists if find_by_name name
    valid?(rtype, stuff)
    stuff[:rtype] = rtype
    stuff[:id] = SecureRandom.uuid
    stuff[:meta] = { created: Time.now.iso8601, last_modified: Time.now.iso8601, version: 1 }
    if stuff[:members]
      put_members(stuff[:id], stuff[:members])
      stuff.delete(:members)
    end
    @things << stuff
    stuff
  end

  def update(id, stuff)
    raise NotFound unless thing = find_by_id(id)
    [:id, :meta, :password, :rtype].each { |k| stuff.delete(k) }
    valid?(thing[:rtype], stuff)
    thing.merge! stuff
    thing[:meta][:version] += 1
    thing[:meta][:lastmodified] == Time.now.iso8601
  end

  def remove(id)
    raise NotFound unless thing = find_by_id(id)
    @things.delete(thing)
  end

  def find_by_id(id, rtype = nil)
    return unless id
    return unless i = @things.index { |thing| thing[:id] == id }
    @things[i] if !rtype || rtype == @things[i][:rtype]
  end

  def find_by_name(name, rtype = nil)
    return unless name
    return unless i = @things.index { |thing| name.casecmp(thing[NAME_ATTR[thing[:rtype]]]) == 0}
    @things[i] if !rtype || rtype == @things[i][:rtype]
  end

  def members(group_id)
    @things.each_with_object([]) do |thing, members|
        members << thing[:id] if thing[:groups] && thing[:groups].include?(group_id)
    end
  end

  def put_members(group_id, members)
    members.each do |member|
      member = member[:value] if member.is_a? Hash
      thing = find_by_id(member)
      (thing[:groups] ||= []) << group_id
    end
  end

  def things(rtype = nil)
    @things.select { |thing| rtype.nil? || thing[:rtype] == rtype }
  end

  def id_to_name(id)
    thing = find_by_id(id)
    thing[NAME_ATTR[thing[:rtype]]]
  end

  def name_to_id(name)
    thing = find_by_name(name)
    thing[:id]
  end

end

end
