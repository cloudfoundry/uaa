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
require 'cli/config'

module CF::UAA

class BaseCli < Thor
  include Interactive
  include Interactive::Rewindable

  class_option :trace, type: :boolean, aliases: "-t", desc: "display debug information"
  class_option :verbose, type: :boolean, aliases: "-v", desc: "verbose"
  class_option :help, type: :boolean, aliases: "-h", desc: "help"

  private

  def trace?
    options.key?('trace') ? options['trace'] : Config.opts[:trace]
  end

  def auth_header
    "#{Config.opts[:token_type]} #{Config.opts[:access_token]}"
  end

  def verified_pwd(prompt, pwd)
    while pwd.nil?
      pwd_a = ask(prompt, echo: "*", forget: true)
      pwd_b = ask("Verify #{prompt}", echo: "*", forget: true)
      pwd = pwd_a if pwd_a == pwd_b
    end
    pwd
  end

  def name_pwd(username, pwd)
    [ username || ask("User name"), verified_pwd("Password", pwd) ]
  end

end

end
