require "bundler/gem_tasks"
require "rspec/core/rake_task"
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
