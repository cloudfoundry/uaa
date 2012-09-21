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

require 'cli/token'
require 'cli/user'
require 'cli/group'
require 'cli/info'
require 'cli/client_reg'

module CF::UAA

class Cli < BaseCli
  @overview = "UAA Command Line Interface"
  @topics = [MiscCli, InfoCli, TokenCli, UserCli, GroupCli, ClientCli]
  @global_options = [:help, :version, :debug, :trace, :config]

  def self.configure(config_file = "", input = $stdin, output = $stdout)
    @config_file, @input, @output = config_file, input, output
    self
  end

  def self.too_many_args(cmd)
    @output.puts "\nToo many command line parameters given."
    run cmd.unshift("help")
  end

  def self.preprocess_options(args, opts)
    return args.replace(["version"]) if opts[:version]
    return args.unshift("help") if args.empty? || opts[:help] && args[0] != "version"
    Config.load(opts[:config] || @config_file) if opts.key?(:config) || !Config.loaded?
    [:trace, :debug].each do |k|
      opts[k] = true if !opts.key?(k) && Config.target && Config.context && Config.value(k)
    end
    Misc.logger = Util.default_logger(opts[:trace]? :trace: opts[:debug]? :debug: :warn, @output)
  end

end

end
