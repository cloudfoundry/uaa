# -*- encoding: utf-8 -*-
$:.unshift File.expand_path('../lib', __FILE__)
require "csm/version"

Gem::Specification.new do |s|
  s.name        = "csm"
  s.version     = CSM::VERSION
  s.authors     = ["Dale Olds"]
  s.email       = ["daleolds@gmail.com"]
  s.homepage    = ""
  s.summary     = %q{TODO: Write a gem summary}
  s.description = %q{TODO: Write a gem description}
  s.executables = %w(csm)

  s.rubyforge_project = "csm"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency "sinatra"
  s.add_dependency "thin"
  s.add_dependency "datamapper"
  s.add_dependency "dm-sqlite-adapter"
  
  s.add_development_dependency "rspec"
end
