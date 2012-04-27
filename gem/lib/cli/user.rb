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
require 'interact'
require 'cli/base'
require 'uaa'

module CF::UAA

class UserCli < BaseCli

  desc "add [username] [password]", "adds a user account"
  map "a" => "add"
  method_option :given_name, type: :string, aliases: "-g"
  method_option :family_name, type: :string, aliases: "-f"
  method_option :email, type: :string, aliases: "-e"
  def add(username = nil, pwd = nil)
    return help(__method__) if options[:help]
    username, pwd = name_pwd(username, pwd)
    email = options[:email] || (username if username =~ /@/)
    gname = options[:given_name] || username
    fname = options[:family_name] || username
    Config.pp acct_request { |ua| ua.create(username, pwd, email, gname, fname) }
  end

  desc "list [attributes] [filter]", "list user accounts"
  map "l" => "list"
  def list(attributes = nil, filter = nil)
    return help(__method__) if options[:help]
    Config.pp acct_request { |ua| ua.query(attributes, filter) }
  end

  desc "delete [username]", "delete user account"
  map "d" => "delete"
  def delete(username = nil)
    return help(__method__) if options[:help]
    username ||= ask("User name")
    acct_request { |ua| ua.delete_by_name(username) }
  end

  desc "get [username]", "get user account information"
  map "g" => "get"
  def get(username = nil)
    return help(__method__) if options[:help]
    username ||= ask("User name")
    Config.pp acct_request { |ua| ua.get_by_name(username) }
  end

  desc "password [username] [pwd]", "set password"
  map "p" => "password"
  def password(username = nil, pwd = nil)
    return help(__method__) if options[:help]
    username, pwd = name_pwd(username, pwd)
    Config.pp acct_request { |ua| ua.change_password_by_name(username, pwd) }
  end

  desc "info", "get authenticated user information"
  map "i" => "info"
  def userinfo
    return help(__method__) if options[:help]
    Config.pp id_request { |id| id.user_info }
  end

  private

  def acct_request
    return yield CF::UAA::UserAccount.new(Config.target, auth_header, trace?)
  rescue CF::UAA::TargetError => e
    puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    puts e.message, (e.backtrace if trace?)
  end

  def id_request
    return yield CF::UAA::IdToken.new(Config.target, auth_header, trace?)
  rescue CF::UAA::TargetError => e
    puts "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
  rescue Exception => e
    puts e.message, (e.backtrace if trace?)
  end

end

end
