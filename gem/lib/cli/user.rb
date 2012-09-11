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

  define_option :given_name, "--given_name <name>"
  define_option :family_name, "--family_name <name>"
  define_option :email, "--email <address>"
  define_option :groups, "--groups <groups>"
  USER_INFO_OPTS = [:given_name, :family_name, :email, :groups]

  desc "users [attributes] [filter]", "List user accounts" do |attributes, filter|
    pp acct_request { |ua| ua.query(attributes, filter) }
  end

  desc "user get [name]", "Get specific user account" do |name|
    pp acct_request { |ua| ua.get_by_name(username(name)) }
  end

  desc "user add [name]", "Add a user account", USER_INFO_OPTS + [:password] do |name|
    name = username(name)
    email = opts[:email] || (name if name =~ /@/)
    gname = opts[:given_name] || name
    fname = opts[:family_name] || name
    pwd = verified_pwd("Password", opts[:password])
    pp acct_request { |ua| ua.create(name, pwd, email, gname, fname, opts[:groups]) }
  end

  desc "user delete [name]", "Delete user account" do |name|
    pp acct_request { |ua| ua.delete_by_name(username(name)) }
  end

  desc "password set [name]", "Set password", [:password] do |name|
    pp acct_request { |ua| ua.change_password_by_name(username(name),
        verified_pwd("New password", opts[:password])) }
  end

  define_option :old_password, "-o", "--old_password <password>", "current password"
  desc "password change", "Change password for authenticated user in current context", [:old_password, :password] do
    pp acct_request { |ua|
      oldpwd = opts[:old_password] || ask_pwd("Current password")
      ua.change_password(Config.value(:user_id),
          verified_pwd("New password", opts[:password]), oldpwd)
    }
  end

  private

  def acct_request
    return yield UserAccount.new(Config.target, auth_header)
  rescue TargetError => e
    "\n#{e.message}:\n#{JSON.pretty_generate(e.info)}\n"
  rescue Exception => e
    "\n#{e.class}: #{e.message}\n#{e.backtrace if trace?}\n"
  end

end

end
