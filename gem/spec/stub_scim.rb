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

  private

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
        :refresh_token_validity, :redirect_uri],
      group: COMMON_ATTRS + [:members, :owners, :readers] }

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
    (t = @things_by_id[id]) && (rtype.nil? || t[:rtype] == rtype)
  end

  def valid_ids?(value, rtype = nil)
    return unless value.is_a?(Array)
    value.each do |ref|
      return unless ref.is_a?(String) && valid_id?(ref, rtype) ||
          ref.is_a?(Hash) && ref.key?(:value) && valid_id?(ref[:value], rtype)
    end
  end

  def enforce_schema(rtype, thing)
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

  def members(group_id)
    @things_by_id.each_with_object([]) do |(k, t), members|
        members << t[:id] if t[:groups] && t[:groups].include?(group_id)
    end
  end

  def put_members(group_id, members)
    members.each do |member|
      member = member[:value] if member.is_a? Hash
      thing = ref_by_id(member)
      (thing[:groups] ||= []) << group_id
    end
  end

  def ref_by_id(id, rtype = nil)
    (t = @things_by_id[id]) && (rtype.nil? || t[:rtype] == rtype) ? t : nil
  end

  def ref_by_name(name, rtype)
    @things_by_name[rtype.to_s + name.downcase]
  end

  public

  def initialize
    @things_by_id, @things_by_name = {}, {}
  end

  def add(rtype, stuff)
    unless stuff.is_a?(Hash) && (name = stuff[NAME_ATTR[rtype]])
      raise SchemaViolation, "new #{rtype} has no name #{NAME_ATTR[rtype]}"
    end
    raise AlreadyExists if @things_by_name.key?(name = rtype.to_s + name.downcase)
    enforce_schema(rtype, stuff)
    stuff = stuff.merge(rtype: rtype, id: (id = SecureRandom.uuid),
        meta: { created: Time.now.iso8601, last_modified: Time.now.iso8601, version: 1 })
    if stuff[:members]
      put_members(id, stuff[:members])
      stuff.delete(:members)
    end
    @things_by_id[id] = @things_by_name[name] = stuff
    id
  end

  def update(id, stuff)
    raise NotFound unless thing = ref_by_id(id)
    rtype = thing[:rtype]
    if newname = stuff[NAME_ATTR[rtype]]
      oldname = rtype.to_s + thing[NAME_ATTR[rtype]].downcase
      if (newname = rtype.to_s + newname.downcase) == oldname
        newname = nil
      else
        raise AlreadyExists if @things_by_name.key?(newname)
      end
    end
    stuff = stuff.dup
    [:id, :meta, :rtype].each { |k| stuff.delete(k) }
    enforce_schema(rtype, stuff)
    if stuff[:members]
      put_members(id, stuff[:members])
      stuff.delete(:members)
    end
    if newname
      @things_by_name.delete(oldname)
      @things_by_name[newname] = thing
    end
    thing.merge! stuff
    thing[:meta][:version] += 1
    thing[:meta][:lastmodified] == Time.now.iso8601
  end

  def remove(id, rtype = nil)
    return unless thing = ref_by_id(id, rtype)
    @things_by_id.delete(id)
    rtype = thing[:rtype]
    @things_by_name.delete(rtype.to_s + thing[NAME_ATTR[rtype]].downcase)
  end

  def get(id, rtype = nil)
    return unless thing = ref_by_id(id, rtype)
    thing = thing.dup
    thing[:members] = members(id) if thing[:rtype] == :group
    thing
  end

  def name(id, rtype = nil)
    return unless thing = ref_by_id(id, rtype)
    thing[NAME_ATTR[thing[:rtype]]]
  end

  def id(name, rtype)
    return unless thing = ref_by_name(name, rtype)
    thing[:id]
  end

  def get_by_name(name, rtype) ; get(id(name, rtype)) end

  def find(rtype, filter = nil)
    @things_by_id.each_with_object([]) { |(k, v), o| o << v[:id] if rtype == v[:rtype] }
  end

end

end
