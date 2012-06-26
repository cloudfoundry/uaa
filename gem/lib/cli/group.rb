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

  topic "Groups"

  desc "groups [<attributes>] [<filter>]", "List groups" do |attributes, filter|
    pp group_request { |gr| gr.query(attributes, filter) }
  end

  desc "group get [<name>]", "Get specific group information" do |name|
    name ||= ask("Group name")
    pp group_request { |gr| gr.get_by_name(name) }
  end

  desc "group add [<name>]", "Adds a group" do |name|
    pp group_request { |gr| gr.create(name) }
  end

  desc "group delete [<name>]", "Delete group" do |name|
    name ||= ask("Group name")
    group_request { |gr| gr.delete_by_name(name) }
  end

  private

  def group_request
    #return yield UserAccount.new(cur_target_url, auth_header, trace?)
  #rescue TargetError => e
    #say "#{e.message}:\n#{JSON.pretty_generate(e.info)}"
    #nil
  #rescue Exception => e
    #say e.message, (e.backtrace if trace?)
    #nil
  end

end

end
