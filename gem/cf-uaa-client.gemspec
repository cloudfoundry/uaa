# -*- encoding: utf-8 -*-
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

$:.push File.expand_path("../lib", __FILE__)
require "uaa/version"

Gem::Specification.new do |s|
  s.name        = "cf-uaa-client"
  s.version     = CF::UAA::VERSION
  s.authors     = ["Dave Syer", "Dale Olds", "Joel D'sa", "Vidya Valmikinathan", "Luke Taylor"]
  s.email       = ["dsyer@vmware.com", "olds@vmware.com", "jdsa@vmware.com", "vidya@vmware.com", "ltaylor@vmware.com"]
  s.homepage    = "https://github.com/cloudfoundry/uaa/tree/master/gem"
  s.summary     = %q{Deprecated client and resource library for CloudFoundry UAA. Please use cf-uaa-lib and cf-uaac instead.}
  s.description = %q{Deprecated client library and command line tools for interacting with the CloudFoundry User Account and Authorization (UAA) server.  The UAA is an OAuth2 Authorization Server so it can be used by webapps and command line apps to obtain access tokens to act on behalf of users.  The tokens can then be used to access protected resources in a Resource Server.  This library can be used by clients (as a convenient wrapper for mainstream oauth gems) or by resource servers.}

  s.rubyforge_project = "cf-uaa-client"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  # dependencies
  s.add_development_dependency "bundler"
  s.add_development_dependency "rake"
  s.add_development_dependency "rspec"
  s.add_development_dependency "simplecov"
  s.add_development_dependency "simplecov-rcov"
  s.add_development_dependency "ci_reporter"
  s.add_runtime_dependency "highline"
  s.add_runtime_dependency "rest-client"
  s.add_runtime_dependency "yajl-ruby"
  s.add_runtime_dependency "eventmachine"
  s.add_runtime_dependency "launchy"
  s.add_runtime_dependency "em-http-request", ">= 1.0.0.beta.3"

end
