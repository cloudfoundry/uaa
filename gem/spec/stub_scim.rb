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

require 'set'
require 'time'
require 'uaa/util'

module CF::UAA

class SchemaViolation < RuntimeError; end
class AlreadyExists < RuntimeError; end
class BadFilter < RuntimeError; end
class BadVersion < RuntimeError; end

class StubScim

  private

  # attribute types. Anything not listed is case-ignore string
  HIDDEN_ATTRS = [:rtype, :password, :client_secret]
  READ_ONLY_ATTRS = [:id, :meta, :groups]
  BOOLEANS = [:active]
  NUMBERS = [:access_token_validity, :refresh_token_validity]
  GROUPS = [:groups, :auto_approved_scope, :scope, :authorities]
  REFERENCES = [:members, :owners, :readers] + GROUPS # references to users or groups
  ENUMS = { authorized_grant_types: ["client_credentials", "implicit",
      "authorization_code", "password", "refresh_token"] }
  GENERAL_MULTI = [:emails, :phonenumbers, :ims, :photos, :entitlements,
      :roles, :x509certificates]
  GENERAL_SUBATTRS = [:value, :display, :primary, :type]
  EXPLICIT_SINGLE = {
      name: [:formatted, :familyname, :givenname, :middlename,
          :honorificprefix, :honorificsuffix],
      meta: [:created, :lastmodified, :location, :version] }
  EXPLICIT_MULTI = {
      addresses: [:formatted, :streetaddress, :locality, :region,
          :postal_code, :country, :primary, :type],
      authorizations: [:client_id, :group, :exp] }

  # resource class definitions: naming and legal attributes
  NAME_ATTR = { user: :username, client: :client_id, group: :displayname }
  COMMON_ATTRS = [:externalid, :id, :meta]
  LEGAL_ATTRS = {
      user: COMMON_ATTRS + [:displayname, :username, :nickname,
        :profileurl, :title, :usertype, :preferredlanguage, :locale,
        :timezone, :active, :password, :emails, :phonenumbers, :ims, :photos,
        :entitlements, :roles, :x509_certificates, :name, :addresses,
        :authorizations, :groups],
      client: COMMON_ATTRS + [:client_id, :client_secret, :authorized_grant_types,
        :scope, :auto_approved_scope, :access_token_validity,
        :refresh_token_validity, :redirect_uri, :authorities],
      group: COMMON_ATTRS + [:displayname, :members, :owners, :readers] }
  VISIBLE_ATTRS = {user: LEGAL_ATTRS[:user] - HIDDEN_ATTRS,
      client: LEGAL_ATTRS[:client] - HIDDEN_ATTRS, group: LEGAL_ATTRS[:group] - HIDDEN_ATTRS}

  def self.searchable_attribute(attr)
    attr = attr.to_sym
    return false if HIDDEN_ATTRS.include?(attr)
    LEGAL_ATTRS.each { |k, v| v.each { |a| return a if a == attr } }
    false
  end

  def self.remove_hidden(attrs = nil) attrs - HIDDEN_ATTRS if attrs end

  def hide_attrs(thing, attrs = HIDDEN_ATTRS) attrs.each { |a| thing.delete(a) }; thing end
  def valid_id?(id, rtype) id && (t = @things_by_id[id]) && (rtype.nil? || t[:rtype] == rtype) end
  def ref_by_name(name, rtype) @things_by_name[rtype.to_s + name.downcase] end

  def ref_by_id(id, rtype = nil)
    (t = @things_by_id[id]) && (rtype.nil? || t[:rtype] == rtype) ? t : nil
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

  def valid_ids?(value, rtype = nil)
    return unless value.is_a?(Array)
    value.each do |ref|
      return unless ref.is_a?(String) && valid_id?(ref, rtype) ||
          ref.is_a?(Hash) && valid_id?(ref[:value], rtype)
    end
  end

  def enforce_schema(rtype, thing)
    thing.each do |k, v|
      raise SchemaViolation, "illegal #{k} on #{rtype}" unless LEGAL_ATTRS[rtype].include?(k)
      raise SchemaViolation, "attempt to modify read-only attribute #{k} on #{rtype}" if READ_ONLY_ATTRS.include?(k)
      valid_attr = case k
        when *BOOLEANS then v == !!v
        when *NUMBERS then v.is_a?(Integer)
        when *GENERAL_MULTI then valid_multi?(v, GENERAL_SUBATTRS, true)
        when *GROUPS then valid_ids?(v, :group)
        when *REFERENCES then valid_ids?(v)
        when ENUMS[k] then ENUMS[k].include?(v)
        when *EXPLICIT_SINGLE.keys then valid_complex?(v, EXPLICIT_SINGLE[k])
        when *EXPLICIT_MULTI.keys then valid_multi?(v, EXPLICIT_MULTI[k])
        else k.is_a?(String) || k.is_a?(Symbol)
      end
      raise SchemaViolation, "#{v} is an invalid #{k}" unless valid_attr
    end
  end

  def input!(thing)
    REFERENCES.each {|a|
      next unless thing[a]
      thing[a] = thing[a].each_with_object(Set.new) { |r, s| s << (r.is_a?(Hash)? r[:value] : r )}
    }
    GENERAL_MULTI.each {|a|
      next unless thing[a]
      thing[a] = thing[a].each_with_object({}) {|v, o|
        v = {value: v} unless v.is_a?(Hash)
        k = URI.encode_www_form(t: [v[:type], v: v[:value]]).downcase # enforce values are unique by type and value
        o[k] = v
      }
    }
  end

  def output(thing, attrs)
    attrs = thing.keys if attrs.nil? || attrs.empty?
    attrs.each_with_object({}) {|a, o|
      next unless thing[a]
      case a
      when *REFERENCES then o[a] = thing[a].to_a
      when *GENERAL_MULTI then o[a] = thing[a].values
      else o[a] = thing[a]
      end
    }
  end

  def add_user_groups(gid, members)
    members.each {|m| (m[:groups] ||= Set.new) << gid if m = ref_by_id(m, :user)} if members
  end

  def remove_user_groups(gid, members)
    members.each {|m| m[:groups].delete(gid) if m = ref_by_id(m, :user) } if members
  end

  public

  def initialize; @things_by_id, @things_by_name = {}, {} end
  def name(id, rtype = nil) (t = ref_by_id(id, rtype))? t[NAME_ATTR[t[:rtype]]]: nil end
  def id(name, rtype) (t = ref_by_name(name, rtype))? t[:id] : nil end

  def add(rtype, stuff)
    unless stuff.is_a?(Hash) && (name = stuff[NAME_ATTR[rtype]])
      raise SchemaViolation, "new #{rtype} has no name #{NAME_ATTR[rtype]}"
    end
    raise AlreadyExists if @things_by_name.key?(name = rtype.to_s + name.downcase)
    enforce_schema(rtype, stuff)
    stuff.merge!(rtype: rtype, id: (id = SecureRandom.uuid),
        meta: { created: Time.now.iso8601, last_modified: Time.now.iso8601, version: 1 })
    input!(stuff)
    add_user_groups(id, stuff[:members])
    @things_by_id[id] = @things_by_name[name] = stuff
    id
  end

  def update(id, stuff, match_version = nil, match_type = nil)
    raise NotFound unless thing = ref_by_id(id, match_type)
    raise BadVersion if match_version && match_version != thing[:meta][:version]
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
    hide_attrs(stuff, [:rtype] + READ_ONLY_ATTRS)
    enforce_schema(rtype, stuff)
    if newname
      @things_by_name.delete(oldname)
      @things_by_name[newname] = thing
    end
    input!(stuff)
    if stuff[:members]
      members = thing[:members] || Set.new
      remove_user_groups(id, members - stuff[:members])
      add_user_groups(id, stuff[:members] - members)
    end
    thing.merge! stuff
    thing[:meta][:version] += 1
    thing[:meta][:lastmodified] == Time.now.iso8601
    id
  end

  def add_member(gid, member)
    return unless g = ref_by_id(gid, :group)
    (g[:members] ||= Set.new) << member
    add_user_groups(gid, Set[member])
  end

  def remove(id, rtype = nil)
    return unless thing = ref_by_id(id, rtype)
    @things_by_id.delete(id)
    rtype = thing[:rtype]
    remove_user_groups(id, thing[:members])
    hide_attrs(@things_by_name.delete(rtype.to_s + thing[NAME_ATTR[rtype]].downcase))
  end

  def get(id, rtype = nil, *attrs)
    return unless thing = ref_by_id(id, rtype)
    output(thing, attrs)
  end

  def get_by_name(name, rtype, *attrs)
    return unless thing = ref_by_name(name, rtype)
    output(thing, attrs)
  end

  def find(rtype, start = 0, count = nil, filter_string = nil, attrs = nil)
    filter, total = ScimFilter.new(filter_string), 0
    objs = @things_by_id.each_with_object([]) { |(k, v), o|
      next unless rtype == v[:rtype] && filter.match?(v)
      o << output(v, attrs) if total >= start && (count.nil? || o.length < count)
      total += 1
    }
    [objs, total]
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
    (attr_sym = StubScim.searchable_attribute(attr)) ?
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
    return true if op == "pr"
    case attr
    when *StubScim::REFERENCES
      return nil unless op == "eq"
      val.each {|v| return true if v.casecmp(value) == 0 }
      false
    when *StubScim::GENERAL_MULTI
      return nil unless op == "eq"
      val.each {|k, v| return true if v.casecmp(value) == 0 }
      false
    else
      case op
      when "eq"; val.casecmp(value) == 0
      when "sw"; val =~ /^#{Regexp.escape(value)}/i
      when "co"; val =~ /#{Regexp.escape(value)}/i
      when "gt"; val.casecmp(value) > 0
      when "ge"; val.casecmp(value) >= 0
      when "lt"; val.casecmp(value) < 0
      when "le"; val.casecmp(value) <= 0
      end
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
    if filter_string.nil?
      @filter = true
    else
      @input = StringScanner.new(filter_string)
      @filter = eat_phrase
      raise BadFilter unless @input.eos?
    end
    self
  rescue BadFilter => b
    raise BadFilter, "invalid filter expression at offset #{@input.pos}: #{@input.string}"
  end

  def match?(entry)
    @filter == true || eval(entry, @filter)
  end

end

end
