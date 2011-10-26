require 'rake'
require 'spec/rake/spectask'

desc "Run specs"
task :spec do
  sh('bundle install')
  Spec::Rake::SpecTask.new('spec') do |t|
    t.spec_opts = %w(-fs -c)
    t.spec_files = FileList['spec/**/*_spec.rb']
  end
end

desc "Synonym for spec"
task :test => :spec
desc "Synonym for spec"
task :tests => :spec
task :default => :spec
