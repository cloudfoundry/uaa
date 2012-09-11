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
#require "bundler/gem_tasks" # only available in bundler >= 1.0.15
#require "rdoc/task" # rdoc for current interfaces not written yet
require "ci/reporter/rake/rspec"

ENV['CI_REPORTS'] = File.expand_path("spec_reports")

task :default => [:test]
task :tests => [:test]
task :spec => [:test]

RSpec::Core::RakeTask.new("test") do |t|
  t.rspec_opts = ["--format", "documentation", "--colour"]
  t.pattern = "spec/**/*_spec.rb"
end

#RDoc::Task.new do |rd|
#  rd.rdoc_files.include("lib/**/*.rb")
#  rd.rdoc_dir = "doc"
#end

task :ci => [:pre_coverage, :rcov_reports, "ci:setup:rspec", :test]
task :cov => [:pre_coverage, :test, :view_coverage]
task :coverage => [:pre_coverage, :test]

task :pre_coverage do
  rm_rf "coverage"
  ENV['COVERAGE'] = "exclude-spec exclude-vendor"
end

task :rcov_reports do
  ENV['COVERAGE'] += " rcov"
end

task :view_coverage do
  `firefox #{File.join(File.dirname(__FILE__), 'coverage', 'index.html')}`
end
