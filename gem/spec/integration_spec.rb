#--
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
#++

require 'spec_helper'
require 'uaa'

#ENV["UAA_CLIENT_ID"] = "admin"
#ENV["UAA_CLIENT_SECRET"] = "adminclientsecret"
#ENV["UAA_CLIENT_TARGET"] = "http://localhost:8080/uaa"

if ENV["UAA_CLIENT_ID"] && ENV["UAA_CLIENT_SECRET"] && ENV["UAA_CLIENT_TARGET"]

  describe "UAA Integration:" do

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

    context "with a client credentials grant, " do

      before :all do
        toki = Cloudfoundry::Uaa::TokenIssuer.new(@target, @client_id,
            @client_secret, "read write password", "scim")
        toki.trace = true
        tokn = toki.client_credentials_grant
        @user_acct = Cloudfoundry::Uaa::UserAccount.new(@target, tokn)
        @user_acct.trace = true
        @username = "sam_#{Time.now.to_i}"
      end

      it "creates a user" do
        usr = @user_acct.create(@username, "joe's password", "joe@example.com")
        puts usr
        ENV["UAA_USER_ID"] = usr[:id] # need a better way
        puts usr[:id]
      end

      it "finds the user by name" do
        user_info = @user_acct.query_by_value("id", "username", @username)
        puts JSON.pretty_generate(user_info)
        puts user_info
      end

      it "gets the user by id" do
        user_id = ENV["UAA_USER_ID"]
        user_info = @user_acct.get(user_id)
        puts JSON.pretty_generate(user_info)
        puts user_info[:meta][:version]
      end

      it "changes the user's password by name" do
        @user_acct.change_password_by_name(@username, "newpassword")
      end

      it "lists all users" do
        user_info = @user_acct.list
        puts JSON.pretty_generate(user_info)
      end

      it "deletes the user by name" do
        @user_acct.delete_by_name(@username)
        expect { @user_acct.get_by_name(@username) }
            .to raise_exception(Cloudfoundry::Uaa::UserAccount::NotFound)
      end

      it "complains about an attempt to delete a non-existent user" do
        expect { @user_acct.delete_by_name("non-existent-user") }
            .to raise_exception(Cloudfoundry::Uaa::UserAccount::NotFound)
      end

    end

  end

end
