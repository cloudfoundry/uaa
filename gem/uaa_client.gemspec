# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "uaa/version"

Gem::Specification.new do |s|  
  s.name        = "uaa_client"
  s.version     = Cloudfoundry::Uaa::VERSION
  s.authors     = ["Dave Syer"]
  s.email       = ["dsyer@vmware.com"]
  s.homepage    = ""
  s.summary     = %q{Client and resource library for Cloudfoundry UAA}
  s.description = %q{Client library and command line tools for interacting with  the Cloudfoundry User Account and Authorization (UAA) server.  The UAA is an OAuth2 Authorization Server so it can be used by webapps and command line apps to obtain access tokens to act on behalf of users.  The tokens can then be used to access protected resources in a Resource Server.  This library can be used by clients (as a convenient wrapper for mainstream oauth gems) or by resource servers.}

  s.rubyforge_project = "uaa_client"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  # specify any dependencies here; for example:
  s.add_development_dependency "rspec"
  s.add_development_dependency "bundler"
  s.add_development_dependency "simplecov"
  s.add_development_dependency "highline"
  s.add_runtime_dependency "rest-client"
  s.add_runtime_dependency "json_pure"
end
