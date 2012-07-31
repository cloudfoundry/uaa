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

if ENV['COVERAGE']
  require "simplecov"
  if ENV['COVERAGE'] =~ /rcov/
    require "simplecov-rcov"
    SimpleCov.formatter = SimpleCov::Formatter::RcovFormatter
  end
  SimpleCov.add_filter "^#{File.dirname(__FILE__)}" if ENV['COVERAGE'] =~ /exclude-spec/
  SimpleCov.add_filter "^#{File.expand_path(File.join(File.dirname(__FILE__), "..", "vendor"))}" if ENV['COVERAGE'] =~ /exclude-vendor/
  SimpleCov.start
end

require 'rspec'
require 'eventmachine'

module SpecHelper

  def capture_exception
    yield
  rescue Exception => e
    e
  end

  # runs given block on a thread or fiber and returns result
  # if eventmachine is running on another thread, the fiber
  # must be on the same thread, hence EM.schedule and the
  # restriction that the given block cannot include rspec matchers.
  def frequest(&blk)
    return capture_exception(&blk) unless @async
    result = nil
    cthred = Thread.current
    EM.schedule { Fiber.new { result = capture_exception(&blk); cthred.run }.resume }
    Thread.stop
    result
  end

end
