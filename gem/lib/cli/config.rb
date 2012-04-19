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

require 'thor'
require 'yaml'
require 'uaa/http'

class CliCfg
  CONFIG_FILE = "#{ENV['HOME']}/.uaac.yml"

  def self.start
    @config = File.exists?(CONFIG_FILE) ? CF::UAA.rubyize_keys(YAML.load_file(CONFIG_FILE)) : {}
    @curtgt = nil
    @config.each {|k, v| @curtgt ||= k if v[:current_target] }
  end

  def self.save
    File.open(CONFIG_FILE, 'w') { |f| YAML.dump(CF::UAA.unrubyize_keys(@config), f) }
  end

  def self.pp(obj)
    #puts JSON.pretty_generate(CF::UAA.unrubyize_keys(obj))
    puts YAML.dump(CF::UAA.unrubyize_keys(obj))
  end

  def self.normalize_url url
    raise ArgumentError, "invalid whitespace in target url" if url =~ /\s/
    uri = URI.parse(url =~ /^https?:\/\// ? url: "https://#{url}")
    uri.host.downcase!
    uri.to_s
  end

  def self.set_target(url, client_id)
    raise ArgumentError, "invalid target and client" unless url && client_id
    @config[@curtgt].delete(:current_target) if @curtgt
    @curtgt = "#{normalize_url(url)} #{client_id}".to_sym
    @config[@curtgt] ||= {}
    @config[@curtgt][:current_target] = true
    save
  end

  def self.clear_target(url, client_id)
    tgt = "#{normalize_url(url)} #{client_id}".to_sym
    @curtgt = nil if tgt == @curtgt
    @config.delete(tgt)
    save
  end

  def self.target
    @curtgt.to_s.split[0] if @curtgt
  end

  def self.client_id
    @curtgt.to_s.split[1] if @curtgt
  end

  def self.opts(hash = nil)
    raise ArgumentError, "target not set" unless @curtgt
    if hash
      @config[@curtgt].merge! hash
      save
    end
    @config[@curtgt]
  end

  def self.dump
    pp @config
  end

end

CliCfg.start
