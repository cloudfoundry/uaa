#
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
#

if ENV['COVERAGE']
  require "simplecov"
  SimpleCov.start
end

require 'rspec'

def integration_test?
  ENV['INTEGRATION_TEST']
end

RSpec.configure do |config|
  #only run examples with 'integration' specified in metadata
  config.filter_run(:integration => true) if integration_test?
end

def spec_asset(filename)
  File.expand_path(File.join(File.dirname(__FILE__), "assets", filename))
end
