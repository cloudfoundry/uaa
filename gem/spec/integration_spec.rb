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

# Example config for integration tests with defaults:
#    ENV["UAA_CLIENT_ID"] = "admin"
#    ENV["UAA_CLIENT_SECRET"] = "adminsecret"
# if UAA_CLIENT_TARGET is not configured, tests will use the internal stub server
#    ENV["UAA_CLIENT_TARGET"] = "http://localhost:8080/uaa"

module CF::UAA

describe "UAA Integration:" do

  before :all do
    #Util.default_logger(:trace)
    @client_id = ENV["UAA_CLIENT_ID"] || "admin"
    @client_secret = ENV["UAA_CLIENT_SECRET"] || "adminsecret"
    if ENV["UAA_CLIENT_TARGET"]
      @target, @stub_uaa = ENV["UAA_CLIENT_TARGET"], nil
    else
      @stub_uaa = StubUAA.new(@client_id, @client_secret).run_on_thread
      @target = @stub_uaa.url
    end
    @username = "sam_#{Time.now.to_i}"
    @user_id = ""
  end

  after :all do @stub_uaa.stop if @stub_uaa end

  it "should report the uaa client version" do
    VERSION.should =~ /\d.\d.\d/
  end

  it "makes sure the server is there by getting the prompts for an implicit grant" do
    prompts = TokenIssuer.new(@target, @client_id, @client_secret).prompts
    prompts.should_not be_nil
    #puts "user_info", JSON.pretty_generate(prompts), ""
  end

  it "configures the admin client for the rest of the tests" do
    toki = TokenIssuer.new(@target, @client_id, @client_secret)
    cr = ClientReg.new(@target, toki.client_credentials_grant.auth_header)
    admin_reg = cr.get(@client_id)
    admin_reg[:authorities] = admin_reg[:authorities] | ["scim.read", "scim.write", "password.write"]
    cr.update(admin_reg)
    admin_reg = cr.get(@client_id)
    admin_reg[:authorities].should include("scim.read")
    admin_reg[:authorities].should include("scim.write")
  end

  context "with a client credentials grant," do

    before :all do
      toki = TokenIssuer.new(@target, @client_id, @client_secret)
      @user_acct = UserAccount.new(@target, toki.client_credentials_grant.auth_header)
    end

    it "creates a user" do
      usr = @user_acct.create(@username, "sam's password", "sam@example.com")
      @user_id.replace usr[:id]
      usr[:id].should be
    end

    it "finds the user by name" do
      user_info = @user_acct.query_by_value("id", "username", @username)[:resources][0]
      #puts "user_info", JSON.pretty_generate(user_info), ""
      user_info[:id].should == @user_id
      #user_info[:username].should == @username
    end

    it "gets the user by id" do
      user_info = @user_acct.get(@user_id)
      user_info[:id].should == @user_id
      user_info[:username].should == @username
      #puts JSON.pretty_generate(user_info)
    end

    it "changes the user's password by name" do
      @user_acct.change_password_by_name(@username, "newpassword").should be_nil
    end

    it "lists all users" do
      user_info = @user_acct.query
      user_info.should_not be_nil
      #puts JSON.pretty_generate(user_info)
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
      @toki = TokenIssuer.new(@target, "vmc")
    end

    it "verifies that prompts for the implicit grant are username and password" do
      prompts = @toki.prompts
      prompts[:username].should_not be_nil
      prompts[:password].should_not be_nil
    end

    it "gets a token by an implicit grant" do
      token = @toki.implicit_grant_with_creds(username: @username, password: "newpassword")
      token.info[:access_token].should be
      #puts "token info", JSON.pretty_generate(token.info), ""
      info = Misc.whoami(@target, token.auth_header)
      #puts "user info", JSON.pretty_generate(info), ""
      info[:user_name].should == @username
      contents = TokenCoder.decode(token.info[:access_token], nil, nil, false)
      contents[:user_name].should == @username
      #puts "token contents", JSON.pretty_generate(contents), ""
    end
  end
end

end
