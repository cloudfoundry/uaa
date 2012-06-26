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

require 'yajl/json_gem'
require 'open-uri'

module CF; module UAA; end; end

class CF::UAA::AuthError < RuntimeError; end

class CF::UAA::Util

  # http headers and various protocol tags tend to contain '-' characters
  # and are intended to be case-insensitive -- and often end up as keys in ruby
  # hashes. The :undash style converts these keys to symbols, downcased for at least
  # consistent case if not exactly case insensitive, and with '_' instead
  # of '-' for ruby convention. :todash reverses :undash (except for case).
  # :uncamel and :tocamel provide similar translations for camel-case keys.
  def self.hash_key(k, style)
    case style
    when :undash then k.to_s.downcase.tr('-', '_').to_sym
    when :todash then k.to_s.tr('_', '-')
    when :uncamel then k.to_s.gsub(/([A-Z])([^A-Z]*)/,'_\1\2').downcase.to_sym
    when :tocamel then k.to_s.gsub(/(_[a-z])([^_]*)/) { $1[1].upcase + $2 }
    when :tosym then k.to_s.to_sym
    end
  end

  def self.hash_keys(obj, style)
    return obj.collect {|o| hash_keys(o, style)} if obj.is_a? Array
    return obj unless obj.is_a? Hash
    obj.each_with_object({}) {|(k, v), h| h[hash_key(k, style)] = hash_keys(v, style) }
  end

  def self.json_parse(str, style = :tosym)
    hash_keys(JSON.parse(str), style) if str && !str.empty?
  end

  def self.truncate(obj, limit = 50)
    return obj.to_s if limit == 0
    limit = limit < 5 ? 1 : limit - 4
    str = obj.to_s[0..limit]
    str.length > limit ? str + '...': str
  end

  def self.normalize_url url
    raise ArgumentError, "invalid whitespace in target url" if url =~ /\s/
    uri = URI.parse(url =~ /^https?:\/\// ? url: "https://#{url}")
    uri.host.downcase!
    uri.to_s
  end

  # many parameters in these classes can be given as arrays, or as a list of
  # arguments separated by spaces or commas. This method handles the possible
  # inputs and returns an array of arguments.
  def self.arglist(arg, default_arg = nil)
    arg = default_arg unless arg
    return arg if arg.nil? || arg.respond_to?(:join)
    raise ArgumentError, "arg must be Array or space/comma delimited strings" unless arg.respond_to?(:split)
    arg.split(/[\s\,]+/).reject { |e| e.empty? }
  end

  # reverse of arglist, puts arrays of strings into a single, space-delimited string
  def self.strlist(arg)
    arg.respond_to?(:join) ? arg.join(' ') : arg.to_s
  end

end
