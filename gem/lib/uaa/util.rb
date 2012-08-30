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
require 'logger'
require 'uri'

module CF; module UAA end end

class Logger
  Severity::TRACE = Severity::DEBUG - 1
  def trace(progname, &blk); add(Logger::Severity::TRACE, nil, progname, &blk) end
  def trace? ; @level <= Logger::Severity::TRACE end
end

module CF::UAA

class AuthError < RuntimeError; end

class Util

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
    when :tosym then k.to_s.downcase.to_sym
    when :tostr then k.to_s
    when :none then k
    else raise "unknown hash key style: #{style}"
    end
  end

  def self.hash_keys(obj, style = :tosym)
    return obj.collect {|o| hash_keys(o, style)} if obj.is_a? Array
    return obj unless obj.is_a? Hash
    obj.each_with_object({}) {|(k, v), h| h[hash_key(k, style)] = hash_keys(v, style) }
  end

  # Takes an x-www-form-urlencoded string and returns a hash of symbol => value.
  # Useful for OAuth parameters. It raises an ArgumentError if a key occurs
  # more than once, which is a restriction of OAuth query strings.
  # See draft-ietf-oauth-v2-23 section 3.1.
  def self.decode_form_to_hash(url_encoded_pairs)
    URI.decode_www_form(url_encoded_pairs).each_with_object({}) do |p, o|
      k = p[0].downcase.to_sym
      raise ArgumentError, "duplicate keys in form parameters" if o[k]
      o[k] = p[1]
    end
  rescue Exception => e
    raise ArgumentError, e.message
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

  # many parameters in these classes can be given as arrays, or as a list of
  # arguments separated by spaces or commas. This method handles the possible
  # inputs and returns an array of arguments.
  def self.arglist(arg, default_arg = nil)
    arg = default_arg unless arg
    return arg if arg.nil? || arg.respond_to?(:join)
    raise ArgumentError, "arg must be Array or space|comma delimited strings" unless arg.respond_to?(:split)
    arg.split(/[\s\,]+/).reject { |e| e.empty? }
  end

  # reverse of arglist, puts arrays of strings into a single, space-delimited string
  def self.strlist(arg)
    arg.respond_to?(:join) ? arg.join(' ') : arg.to_s
  end

  def self.default_logger(level = nil, sink = nil)
    if sink || !@default_logger
      @default_logger = Logger.new(sink || $stdout)
      level = :info unless level
      @default_logger.formatter = Proc.new { |severity, time, pname, msg| puts msg }
    end
    @default_logger.level = Logger::Severity.const_get(level.upcase) if level
    @default_logger
  end

end

end
