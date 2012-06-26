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

  topic "System information"

  desc "who am i", "get authenticated user information" do
    pp handle_request { Misc.whoami Config.target, auth_header }
  end

  desc "uaa", "get information about current target uaa" do
    return say "target not set" unless Config.target
    pp handle_request { Misc.server Config.target }
  end

  desc "prompts", "Show prompts for credentials required for implicit grant post" do
    pp handle_request { Misc.server(Config.target)[:prompts] }
  end

  desc "signing key", "get the UAA's token signing key(s)", [:client, :secret] do
    handle_request {
      tkc = Misc.validation_key(Config.target, opts[:client], opts[:secret])
      pp tkc.validation_key
    }
  end

  desc "statistics", "Show UAA's current usage statistics" do
    say "/varz request not implemented"
  end

end

end
