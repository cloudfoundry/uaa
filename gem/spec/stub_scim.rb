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
require 'time'

module CF::UAA

class SchemaViolation < RuntimeError; end
class AlreadyExists < RuntimeError; end
class BadFilter < RuntimeError; end

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

  def self.known_attribute(attr)
    return :id if (attr = attr.downcase) == "id"
    LEGAL_ATTRS.each { |k, v| v.each { |a| return a if a.to_s == attr } }
    false
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
    nil
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

class ScimFilter

  private

  def eat_json_string
    raise BadFilter unless @input.skip(/\s*"/)
    str = ""
    while true
      case
      when @input.scan(/[^\\"]+/); str << @input.matched
      when @input.scan(%r{\\["\\/]}); str << @input.matched[-1]
      when @input.scan(/\\[bfnrt]/); str << eval(%Q{"#{@input.matched}"})
      when @input.scan(/\\u[0-9a-fA-F]{4}/); str << [Integer("0x#{@input.matched[2..-1]}")].pack("U")
      else break
      end
    end
    raise BadFilter unless @input.skip(/"\s*/)
    str
  end

  def eat_word(*words)
    @input.skip(/\s*/)
    return unless s = @input.scan(/(\S+)\s*/)
    w = @input[1].downcase
    return w if words.empty? || words.include?(w)
    @input.unscan
    false
  end

  def eat_expr
    if @input.skip(/\s*\(\s*/)
      phrase = eat_phrase
      raise BadFilter unless @input.skip(/\s*\)\s*/)
      return phrase
    end
    raise BadFilter unless (attr = eat_word) &&
        (op = eat_word("eq", "co", "sw", "pr", "gt", "ge", "lt", "le")) &&
        (op == "pr" || value = eat_json_string)
    (attr_sym = StubScim.known_attribute(attr)) ?
        [:item, attr_sym, op, value] : [:undefined, attr, op, value]
  end

  # AND level
  def eat_subphrase
    phrase = [:and, eat_expr]
    while eat_word("and"); phrase << eat_expr end
    phrase.length == 2 ? phrase[1] : phrase
  end

  # OR level
  def eat_phrase
    phrase = [:or, eat_subphrase]
    while eat_word("or"); phrase << eat_subphrase end
    phrase.length == 2 ? phrase[1] : phrase
  end

  def eval_expr(entry, attr, op, value)
    return false unless val = entry[attr]
    case op
    when "pr"; true
    when "eq"; val == value
    when "sw"; val.start_with?(value)
    when "co"; val.contains(value)
    when "gt"; val > value
    when "ge"; val >= value
    when "lt"; val < value
    when "le"; val <= value
    end
  end

  def eval(entry, filtr)
    undefd = 0
    case filtr[0]
    when :undefined ; nil
    when :item ; eval_expr(entry, filtr[1], filtr[2], filtr[3])
    when :or
      filtr[1..-1].each { |f|
        return true if (res = eval(entry, f)) == true
        undefd += 1 if res.nil?
      }
      filtr.length == undefd + 1 ? nil: false
    when :and
      filtr[1..-1].each { |f|
        return false if (res = eval(entry, f)) == false
        undefd += 1 if res.nil?
      }
      filtr.length == undefd + 1 ? nil: true
    end
  end

  public

  def initialize(filter_string)
    @input = StringScanner.new(filter_string)
    @filter = eat_phrase
    raise BadFilter unless @input.eos?
    self
  rescue BadFilter => b
    raise BadFilter, "invalid filter expression at offset #{@input.pos}: #{@input.string}"
  end

  def evaluate(entry)
    puts "evaluating", entry.inspect, @filter.inspect
    eval(entry, @filter)
  end

end

end
