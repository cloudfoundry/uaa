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

require "rspec/core/rake_task"
require "bundler/gem_tasks"
require "rdoc/task"

task :default => [:cover]

RSpec::Core::RakeTask.new("test") do |test|
  test.rspec_opts = ["--format", "documentation", "--colour"]
  test.pattern = "spec/**/*_spec.rb"
end

RDoc::Task.new do |rd|
  rd.rdoc_files.include("lib/**/*.rb")
  rd.rdoc_dir = "doc"
end

task :cov => [:pre_coverage, :test, :view_coverage]
task :cover => [:pre_coverage, :test]
task :coverage => [:pre_coverage, :test]
task :pre_coverage do
  rm_f "coverage"
  ENV['COVERAGE'] = "true"
end

task :view_coverage do
  `firefox #{File.join(File.dirname(__FILE__), 'coverage', 'index.html')}`
end
