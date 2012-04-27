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

require 'json/pure'

module CF; end

module CF::UAA

  # http headers and various protocol tags tend to contain '-' characters
  # and are intended to be case-insensitive -- and often end up as keys in ruby
  # hashes. This code converts these keys to symbols, downcased for at least
  # consistent case if not exactly case insensitive, and with '_' instead
  # of '-' for ruby convention.
  def self.rubyize_key(k)
    k.to_s.downcase.gsub('-', '_').to_sym
  end

  def self.rubyize_keys(obj)
    return obj.collect {|o| rubyize_keys(o)} if obj.is_a? Array
    return obj unless obj.is_a? Hash
    obj.each_with_object({}) {|(k, v), h| h[rubyize_key(k)] = rubyize_keys(v) }
  end

  # opposite of the above: converts keys from symbols with '_' to strings with '-'
  def self.unrubyize_key(k)
    k.to_s.gsub('_', '-')
  end

  def self.unrubyize_keys(obj)
    return obj.collect {|o| unrubyize_keys(o)} if obj.is_a? Array
    return obj unless obj.is_a? Hash
    obj.each_with_object({}) {|(k, v), h| h[unrubyize_key(k)] = unrubyize_keys(v) }
  end

  def self.json_parse(str)
    rubyize_keys(JSON.parse(str)) if str
  end

  def self.truncate(str, limit = 50)
    stripped = str.to_s.strip[0..limit]
    stripped.length > limit ? stripped + '...': stripped
  end

end
