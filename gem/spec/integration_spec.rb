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
require 'cli/base'
require 'stub_uaa'
require 'pp'

# Example config for integration tests below:
ENV["UAA_CLIENT_ID"] ||= "admin"
ENV["UAA_CLIENT_SECRET"] ||= "adminsecret"
#ENV["UAA_CLIENT_TARGET"] = "http://localhost:8080/uaa"

module CF::UAA

#TODO: finish this
#unless ENV["UAA_CLIENT_TARGET"]
  #stub_uaa = StubUAA.new.run_on_thread
  #admin_group = stub_uaa.scim.add(:group, {display_name: "client_admin"})
  #stub_uaa.scim.add(:client, {display_name: "admin", password: "adminsecret",
      #authorized_grant_types: ["client_credentials"],
      #groups: [admin_group[:id]], access_token_validity: 60 * 60 * 24 * 7 })
  #ENV["UAA_CLIENT_TARGET"] = stub_uaa.url # if not configured, use internal stub server
#end

if ENV["UAA_CLIENT_ID"] && ENV["UAA_CLIENT_SECRET"] && ENV["UAA_CLIENT_TARGET"]

  describe "UAA Integration:" do

    before :all do
      Util.default_logger(:trace)
      @target = ENV["UAA_CLIENT_TARGET"]
      @client_id = ENV["UAA_CLIENT_ID"]
      @client_secret = ENV["UAA_CLIENT_SECRET"]
    end

    it "should report the uaa client version" do
      VERSION.should =~ /\d.\d.\d/
    end

    it "makes sure the server is there by getting the prompts for an implicit grant" do
      prompts = TokenIssuer.new(@target, @client_id, @client_secret).prompts
      prompts.should_not be_nil
      #BaseCli.pp prompts
    end

    it "configures the admin client for the rest of the tests" do
      toki = TokenIssuer.new(@target, @client_id, @client_secret)
      cr = ClientReg.new(@target, toki.client_credentials_grant.auth_header)
      admin_reg = cr.get(@client_id)
      admin_reg[:scope] = (admin_reg[:scope] || [] ) | ["openid", "read", "write", "password"]
      admin_reg[:resource_ids] = admin_reg[:resource_ids] = ["scim", "clients", "openid", "cloud_controller", "password", "tokens"]
      admin_reg[:authorities] = (admin_reg[:authorities] || [] ) | ["ROLE_RESOURCE", "ROLE_CLIENT", "ROLE_ADMIN"]
      admin_reg[:client_secret] = @client_secret
      admin_reg[:authorized_grant_types] = (admin_reg[:authorized_grant_types] || [] ) | ["authorization_code"]
      cr.update(admin_reg)
      admin_reg = cr.get(@client_id)
      pp admin_reg
      admin_reg[:scope].should include("openid")
      admin_reg[:resource_ids].should include("scim")
      admin_reg[:authorities].should include("ROLE_RESOURCE")
    end

    context "with a client credentials grant, " do

      before :all do
        toki = TokenIssuer.new(@target, @client_id, @client_secret)
        @user_acct = UserAccount.new(@target, toki.client_credentials_grant.auth_header)
        ENV["UAA_USER_NAME"] = @username = "sam_#{Time.now.to_i}"
      end

      it "creates a user" do
        usr = @user_acct.create(@username, "sam's password", "sam@example.com")
        ENV["UAA_USER_ID"] = usr[:id] # need a better way
        #TODO: check something!
      end

      it "finds the user by name" do
        user_info = @user_acct.query_by_value("id", "username", @username)
        puts JSON.pretty_generate(user_info)
      end

      it "gets the user by id" do
        user_id = ENV["UAA_USER_ID"]
        user_info = @user_acct.get(user_id)
        puts JSON.pretty_generate(user_info)
        #TODO: check something!
      end

      it "changes the user's password by name" do
        @user_acct.change_password_by_name(@username, "newpassword")
        #TODO: check something!
      end

      it "lists all users" do
        user_info = @user_acct.query
        puts JSON.pretty_generate(user_info)
        #TODO: check something!
      end

      #it "deletes the user by name" do
        #@user_acct.delete_by_name(@username)
        #expect { @user_acct.get_by_name(@username) }
            #.to raise_exception(NotFound)
      #end

      #it "complains about an attempt to delete a non-existent user" do
        #expect { @user_acct.delete_by_name("non-existent-user") }
            #.to raise_exception(NotFound)
      #end

    end

    context "with implicit grant, " do

      before :all do
        @toki = TokenIssuer.new(@target, "vmc", nil, "read write openid password")
      end

      it "verifies that prompts for the implicit grant are username and password" do
        prompts = @toki.prompts
        prompts[:username].should_not be_nil
        prompts[:password].should_not be_nil
      end

      it "gets a token by an implicit grant" do
        token = @toki.implicit_grant_with_creds(username: ENV["UAA_USER_NAME"], password: "newpassword")
        puts "token info", JSON.pretty_generate(token.info), ""
        idt = IdToken.new(@target, token.auth_header, @debug)
        info = idt.user_info
        puts "user info", JSON.pretty_generate(info), ""
        contents = TokenCoder.decode(token.info[:access_token], nil, nil, false)
        puts "token contents", JSON.pretty_generate(contents), ""
        #TODO: check something!
      end
    end
  end

end

end
