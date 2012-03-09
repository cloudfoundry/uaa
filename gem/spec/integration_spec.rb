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

require 'spec_helper'
require 'uaa'

#ENV["UAA_CLIENT_ID"] = "scim"
#ENV["UAA_CLIENT_SECRET"] = "scimsecret"
#ENV["UAA_CLIENT_TARGET"] = "http://localhost:8080/uaa"

if ENV["UAA_CLIENT_ID"] && ENV["UAA_CLIENT_SECRET"] && ENV["UAA_CLIENT_TARGET"]

  describe "UAA Integration Tests" do

    before :all do
      @target = ENV["UAA_CLIENT_TARGET"]
      @client_id = ENV["UAA_CLIENT_ID"]
      @client_secret = ENV["UAA_CLIENT_SECRET"]
    end

    it "should report the uaa client version" do
      Cloudfoundry::Uaa::VERSION.should =~ /\d.\d.\d/
    end

    it "makes sure the server is there by getting the prompts for an implicit grant" do
      toki = Cloudfoundry::Uaa::TokenIssuer.new(@target, @client_id,
          @client_secret, "write", "scim")
      puts toki.prompts
    end

    context "manage users with client credentials grant" do

      before :all do
        toki = Cloudfoundry::Uaa::TokenIssuer.new(@target, @client_id,
            @client_secret, "read", "scim")
        toki.trace = true
        @tokn = toki.client_credentials_grant
      end

      it "creates a user" do
        usr_acct = Cloudfoundry::Uaa::UserAccount.new(@target, @tokn)
        usr_acct.trace = true
        usr = usr_acct.create("joe", "joe's password", "joe@example.com")
        puts usr
      end

    end

  end

end
