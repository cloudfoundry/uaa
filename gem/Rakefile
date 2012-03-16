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

#task :default => [:cover]

task :test => [:webmock_specs, :non_webmock_specs]

RSpec::Core::RakeTask.new("non_webmock_specs") do |test|
  non_webmock_specs = `ls spec/*spec.rb`.split - `grep -l webmock spec/*spec.rb`.split
  test.rspec_opts = ["--format", "documentation", "--colour"] + non_webmock_specs
  test.pattern = ""
end

RSpec::Core::RakeTask.new("webmock_specs") do |test|
  webmock_specs = `grep -l webmock spec/*spec.rb`.split
  test.rspec_opts = ["--format", "documentation", "--colour"] + webmock_specs
  #test.pattern = "spec/**/*_spec.rb"
  test.pattern = ""
end

RDoc::Task.new do |rd|
  rd.rdoc_files.include("lib/**/*.rb")
  rd.rdoc_dir = "doc"
end

task :ci => [:pre_coverage, :rcov_reports, :test]
task :cov => [:pre_coverage, :test, :view_coverage]
task :cover => [:pre_coverage, :test]
task :coverage => [:pre_coverage, :test]
task :pre_coverage do
  rm_rf "coverage"
  ENV['COVERAGE'] = "exclude-spec"
end
task :rcov_reports do
  ENV['COVERAGE'] += " rcov"
end

task :view_coverage do
  `firefox #{File.join(File.dirname(__FILE__), 'coverage', 'index.html')}`
end
