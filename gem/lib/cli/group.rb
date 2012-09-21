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

class GroupCli < CommonCli

  topic "Groups", "group"

  def acct_request
    (yield UserAccount.new(Config.target, auth_header)) || "success"
  rescue TargetError => e
    complain e
  end

  def gname(name) name || ask("Group name") end

  desc "groups [attributes] [filter]", "List groups" do |attributes, filter|
    pp acct_request { |ua| ua.query_groups(attributes, filter) }
  end

  desc "group get [name]", "Get specific group information" do |name|
    pp acct_request { |ua| ua.get_group(gname(name)) }
  end

  desc "group add [name]", "Adds a group" do |name|
    pp acct_request { |ua| ua.add_group(gname(name)) }
  end

  desc "group delete [name]", "Delete group" do |name|
    pp acct_request { |ua| ua.delete_group(gname(name)) }
  end

  desc "group increase [name] [members...]", "add members to a group" do |name, *members|
    pp acct_request { |ua| ua.update_group(gname(name), members: members) }
  end

  desc "group decrease [name] [members...]", "remove members from a group" do |name, *members|
    dm = members.each_with_object([]) { |m, dm| dm << {value: m, operation: "delete"} }
    pp acct_request { |ua| ua.update_group(gname(name), members: dm) }
  end

  desc "group members [name] [username|id...]", "Gets user names and ids for the given users" do |name, *users|
    pp acct_request { |ua| ua.members(name, *users) }
  end



end

end
