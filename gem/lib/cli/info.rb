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

class InfoCli < CommonCli

  topic "System Information", "sys", "info"

  desc "info", "get information about current target" do
    misc_request { pp Misc.server Config.target }
  end

  desc "me", "get authenticated user information" do
    misc_request { pp Misc.whoami Config.target, auth_header }
  end

  desc "prompts", "Show prompts for credentials required for implicit grant post" do
    misc_request { pp update_target_info(Misc.server(Config.target))[:prompts] }
  end

  desc "signing key", "get the UAA's token signing key(s)", :client, :secret do
    misc_request { pp Misc.validation_key(Config.target, clientname, clientsecret) }
  end

  desc "stats", "Show UAA's current usage statistics", :client, :secret do
    misc_request { pp Misc.varz(Config.target, clientname, clientsecret) }
  end

  desc "password strength [password]", "calculate strength score of a password" do |pwd|
    misc_request { pp Misc.password_strength(Config.target, userpwd(pwd)) }
  end

  def misc_request(&blk)
    Misc.logger = Util.default_logger
    Config.target ? handle_request(&blk) : say("target not set")
  end

end

end
