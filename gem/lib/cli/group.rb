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

require 'set'
require 'cli/common'
require 'uaa'

module CF::UAA

class GroupCli < CommonCli

  topic "Groups", "group"

  def acct_request
    (yield UserAccount.new(Config.target, auth_header)) || "success"
  rescue Exception => e
    complain e
  end

  def gname(name) name || ask("Group name") end

  desc "groups [filter]", "List groups", :attrs do |filter|
    pp acct_request { |ua| ua.query_groups(opts[:attrs], filter) }
  end

  desc "group get [name]", "Get specific group information" do |name|
    pp acct_request { |ua| ua.get_group_by_name(gname(name)) }
  end

  desc "group add [name]", "Adds a group" do |name|
    pp acct_request { |ua| ua.add_group(displayName: gname(name)) }
  end

  desc "group delete [name]", "Delete group" do |name|
    pp acct_request { |ua| ua.delete_group(ua.group_id_from_name(gname(name))) }
  end

  def id_set(objs)
    objs.each_with_object(Set.new) {|o, s| s << o[:id] || o[:value] || o[:memberId]}
  end

  desc "member add [name] [members...]", "add members to a group" do |name, *members|
    pp acct_request { |ua|
      group = ua.get_group_by_name(gname(name))
      old_ids = id_set(group[:members] || [])
      new_ids = id_set(ua.ids(*members))
      raise "not all members found, none added" unless new_ids.size == members.size
      group[:members] = (old_ids + new_ids).to_a
      raise "no new members given" unless group[:members].size > old_ids.size
      ua.update_group(group[:id], group)
    }
  end

  desc "member delete [name] [members...]", "remove members from a group" do |name, *members|
    pp acct_request { |ua|
      group = ua.get_group_by_name(gname(name))
      old_ids = id_set(group[:members] || [])
      new_ids = id_set(ua.ids(*members))
      raise "not all members found, none deleted" unless new_ids.size == members.size
      group[:members] = (old_ids - new_ids).to_a
      raise "no existing members to delete" unless group[:members].size < old_ids.size
      ua.update_group(group[:id], group)
    }
  end

end

end
