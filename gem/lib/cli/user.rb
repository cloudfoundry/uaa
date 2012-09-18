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

require 'cli/common'
require 'uaa'

module CF::UAA

class UserCli < CommonCli

  topic "User Accounts", "account"

  define_option :givenName, "--given_name <name>"
  define_option :familyName, "--family_name <name>"
  define_option :emails, "--emails <addresses>"
  define_option :groups, "--groups <groups>"
  define_option :phoneNumbers, "--phones <phone_numbers>"
  USER_INFO_OPTS = [:givenName, :familyName, :emails, :groups, :phoneNumbers]

  def user_opts(info = {})
    [:emails, :groups, :phoneNumbers].each do |o|
      next unless opts[o]
      subattr = o == :groups ? :display : :value # TODO: fix this when group membership is complete
      info[o] = Util.arglist(opts[o]).each_with_object([]) { |v, a| a << {subattr => v} }
    end
    n = [:givenName, :familyName].each_with_object({}) { |o, n| n[o] = opts[o] if opts[o] }
    info[:name] = n unless n.empty?
    info
  end

  def acct_request
    return yield UserAccount.new(Config.target, auth_header)
  rescue TargetError => e
    "\n#{e.message}:\n#{JSON.pretty_generate(e.info)}\n"
  rescue Exception => e
    "\n#{e.class}: #{e.message}\n#{e.backtrace if trace?}\n"
  end

  desc "users [attributes] [filter]", "List user accounts" do |attributes, filter|
    pp acct_request { |ua| ua.query(attributes, filter) }
  end

  desc "user get [name]", "Get specific user account" do |name|
    pp acct_request { |ua| ua.get_by_name(username(name)) }
  end

  desc "user add [name]", "Add a user account", *USER_INFO_OPTS, :password do |name|
    info = {userName: username(name), password: verified_pwd("Password", opts[:password])}
    pp acct_request { |ua| ua.add(user_opts(info)) }
  end

  define_option :del_attrs, "--del_attrs <attr_names>", "list of attributes to delete"
  desc "user update [name]", "Update a user account with specified options",
      *USER_INFO_OPTS, :del_attrs do |name|
    return say "no user updates specified" if (updates = user_opts).empty?
    pp acct_request { |ua|
      info = ua.get_by_name(username(name))
      opts[:del_attrs].each { |a| info.delete(a) } if opts[:del_attrs]
      ua.update(info[:id], info.merge(updates))
    }
  end

  desc "user patch [name] [updates]", "Patch user account with updates in SCIM json format",
      :del_attrs do |name, updates|
    pp acct_request { |ua| ua.update(username(name), Util.json_parse(updates), opts[:del_attrs]) }
  end

  desc "user delete [name]", "Delete user account" do |name|
    pp acct_request { |ua| ua.delete_by_name(username(name)) }
  end

  desc "password set [name]", "Set password", :password do |name|
    pp acct_request { |ua| ua.change_password_by_name(username(name),
        verified_pwd("New password", opts[:password])) }
  end

  define_option :old_password, "-o", "--old_password <password>", "current password"
  desc "password change", "Change password for authenticated user in current context", :old_password, :password do
    pp acct_request { |ua|
      oldpwd = opts[:old_password] || ask_pwd("Current password")
      ua.change_password(Config.value(:user_id),
          verified_pwd("New password", opts[:password]), oldpwd)
    }
  end

end

end
