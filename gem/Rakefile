require "rspec/core/rake_task"
require "bundler/gem_tasks"
require "rdoc/task"

task :default => [:test]

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
  ENV['COVERAGE'] = "true"
end

task :view_coverage do
  `firefox #{File.join(File.dirname(__FILE__), 'coverage', 'index.html')}`
end
