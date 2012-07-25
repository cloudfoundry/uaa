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

  topic "User accounts"

  define_option :given_name, "--given_name <name>"
  define_option :family_name, "--family_name <name>"
  define_option :email, "--email <address>"
  define_option :groups, "--groups <groups>"
  USER_INFO_OPTS = [:given_name, :family_name, :email, :groups]

  desc "users [<attributes>] [<filter>]", "List user accounts" do |attributes, filter|
    pp acct_request { |ua| ua.query(attributes, filter) }
  end

  desc "user add [<name>]", "Add a user account", USER_INFO_OPTS + [:password] do |name|
    email = opts[:email] || (name if name =~ /@/)
    gname = opts[:given_name] || name
    fname = opts[:family_name] || name
    pp acct_request { |ua| ua.create(*user_pwd(name, opts[:password]), email, gname, fname, opts[:groups]) }
  end

  desc "user delete [<name>]", "Delete user account" do |name|
    acct_request { |ua| ua.delete_by_name(name || ask("User name")) }
  end

  desc "user get [<name>]", "Get specific user account" do |name|
    pp acct_request { |ua| ua.get_by_name(name || ask("User to delete")) }
  end

  desc "user password set [<name>]", "Set password", [:password] do |name|
    acct_request { |ua| ua.change_password_by_name(*user_pwd(name, opts[:password])) }
  end

  define_option :old_password, "-o", "--old_password <password>", "current password"
  desc "user password change [<name>]", "Change password", [:old_password, :password] do |name|
    name ||= ask("User name")
    opwd = verified_pwd("Current password", opts[:old_password])
    npwd = verified_pwd("New password", opts[:password])
    # TODO: verify the uaa will take a name instead of id here. If not, how
    # get their own id so they can change their own password?
    handle_request { UserAccount.change_password(Config.target, name, opwd, npwd) }
  end

  private

  def acct_request
    return yield UserAccount.new(Config.target, auth_header)
  rescue TargetError => e
    say "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
    nil
  rescue Exception => e
    say e.message, (e.backtrace if trace?)
    nil
  end

end

end
