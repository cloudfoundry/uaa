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

require 'yaml'
require 'uaa/util'

module CF::UAA

class Config

  class << self
    attr_reader :target, :context
  end

  def self.config; @config ? @config.dup : {} end
  def self.yaml; YAML.dump(Util.hash_keys(@config, :tostr)) end
  def self.target?(tgt); tgt if @config[tgt = subhash_key(@config, tgt)] end

  # if a yaml string is provided, config is loaded from the string, otherwise
  # config is assumed to be a file name to read and store config.
  # config can be retrieved in yaml form from Config.yaml
  def self.load(config = nil)
    @config ||= {}
    return unless config
    if config =~ /^---/ || config == ""
      @config = config == "" ? {} : YAML.load(config)
      @config_file = nil
    elsif File.exists?(@config_file = config)
      @config = YAML.load_file(@config_file)
    end
    @config = Util.hash_keys(@config, :tosym)
    @context = current_subhash(@config[@target][:contexts]) if @target = current_subhash(@config)
  end

  def self.save
    File.open(@config_file, 'w') { |f| YAML.dump(Util.hash_keys(@config, :tostr), f) } if @config_file
    nil
  end

  def self.target=(tgt)
    raise ArgumentError, "invalid target, #{tgt}" unless t = set_current_subhash(@config, tgt, @target)
    @context = current_subhash(@config[t][:contexts])
    save
    @target = t
  end

  def self.context=(ctx)
    raise ArgumentError, "target not set" unless @target
    raise ArgumentError, "invalid context, #{ctx}" unless c = set_current_subhash(@config[@target][:contexts] ||= {}, ctx, @context)
    save
    @context = c
  end

  def self.delete(tgt = nil, ctx = nil)
    if tgt && ctx
      @config[tgt][:contexts].delete(ctx)
      @context = nil if tgt == @target && ctx == @context
    elsif tgt
      @config.delete(tgt)
      @target = @context = nil if tgt == @target
    else
      @target, @context, @config = nil, nil, {}
    end
    save
  end

  def self.add_opts(hash)
    raise ArgumentError, "target and context not set" unless @target && @context
    return unless hash and !hash.empty?
    @config[@target][:contexts][@context].merge! hash
    save
  end

  def self.value(attr)
    raise ArgumentError, "target and context not set" unless @target && @context
    @config[@target][:contexts][@context][attr]
  end

  def self.delete_attr(attr)
    raise ArgumentError, "target and context not set" unless @target && @context
    @config[@target][:contexts][@context].delete(attr)
  end

  def self.current_subhash(hash)
    return unless hash
    key = nil
    hash.each { |k, v| key ? v.delete(:current) : (key = k if v[:current]) }
    key
  end

  # key can be an integer index of the desired subhash or the key symbol or string
  def self.subhash_key(hash, key)
    case key
    when Integer then hash.each_with_index { |(k, v), i| return k if i == key }; nil
    when String then key.to_sym
    when Symbol then key
    else nil
    end
  end

  def self.set_current_subhash(hash, newcurrent, oldcurrent)
    return unless k = subhash_key(hash, newcurrent)
    hash[oldcurrent].delete(:current) if oldcurrent
    (hash[k] ||= {}).merge!(current: true)
    k
  end

end

end
