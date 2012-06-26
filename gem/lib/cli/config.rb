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

  # if a yaml string is provided, config is loaded from the string, otherwise
  # config is assumed to be a file name to read and store config.
  # config can be retrieved in yaml form from Config.yaml
  def self.start(config = nil)
    @yaml = (config if config =~ /^--- / || config == "")
    @config_file = (config unless @yaml)
    cfg = @config_file? (YAML.load_file(@config_file) if File.exists?(@config_file)): (YAML.load(@yaml) if @yaml)
    @config = Util.hash_keys(cfg, :tosym) || {}
    @curtgt = nil
    @config.each {|k, v| @curtgt ||= k if v[:current_target] }
  end

  def self.save
    return @yaml = YAML.dump(@config) unless @config_file
    File.open(@config_file, 'w') { |f| YAML.dump(@config, f) }
  end

  # tgt can by an integer index of the desired target, or the key (symbol)
  def self.find_target(targt)
    tgt = targt
    tgt = @config.each_with_index { |(k, v), i| break k if i == tgt } if tgt.is_a? Integer
    raise ArgumentError, "invalid target #{targt}" unless tgt.is_a? Symbol
    tgt
  end

  # tgt can by an integer index of the desired target, or the key (symbol)
  def self.target=(tgt)
    tgt = find_target(tgt)
    @config[@curtgt].delete(:current_target) if @curtgt
    @config[tgt] ||= {}
    @config[tgt][:current_target] = true
    @curtgt = tgt
    save
  end

  def self.target; @curtgt end
  def self.yaml; @yaml; end
  def self.config; @config.dup; end

  def self.delete_target(targt, key = nil)
    tgt = targt
    raise ArgumentError, "invalid target #{targt}" unless (tgt = find_target(tgt)) && @config[tgt]
    key ? config[tgt].delete(key): @config.delete(tgt)
    @curtgt = nil if tgt == @curtgt
    save
  end

  def self.opts(hash = nil)
    raise ArgumentError, "target not set" unless @curtgt
    unless hash.nil? || hash.empty?
      @config[@curtgt].merge! hash
      save
    end
    @config[@curtgt]
  end

end

end
