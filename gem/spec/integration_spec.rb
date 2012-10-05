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
#ENV["UAA_CLIENT_LOGIN"] = "http://localhost:8080/login"

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
  end

  it "configures the admin client for the rest of the tests" do
    toki = TokenIssuer.new(@target, @client_id, @client_secret)
    cr = ClientReg.new(@target, toki.client_credentials_grant.auth_header)
    admin_reg = cr.get(@client_id)
    admin_reg[:authorities] = admin_reg[:authorities] | ["scim.read", "scim.write", "password.write"]
    admin_reg[:authorized_grant_types] = admin_reg[:authorized_grant_types] | ["authorization_code"]
    cr.update(admin_reg)
    admin_reg = cr.get(@client_id)
    admin_reg[:authorities].should include("scim.read")
    admin_reg[:authorities].should include("scim.write")
    admin_reg[:authorized_grant_types].should include("authorization_code")
  end

  context "with a client credentials grant," do

    before :all do
      toki = TokenIssuer.new(@target, @client_id, @client_secret)
      @user_acct = UserAccount.new(@target, toki.client_credentials_grant.auth_header)
    end

    it "creates a user" do
      usr = @user_acct.add(userName: @username, password: "sam's password",
          emails: [{value: "sam@example.com"}], name: {givenName: "none", familyName: "none"})
      @user_id.replace usr[:id]
      usr[:id].should be
    end

    it "finds the user by name" do
      @user_acct.user_id_from_name(@username).should == @user_id
    end

    it "gets the user by id" do
      user_info = @user_acct.get(@user_id)
      user_info[:id].should == @user_id
      # TODO: fix this after uaa attribute names are no longer case sensitive
      user_info[:username] ? user_info[:username].should == @username : user_info[:userName].should == @username
    end

    it "changes the user's password by name" do
      @user_acct.change_password_by_name(@username, "newpassword")[:status].should == "ok"
    end

    it "lists all users" do
      user_info = @user_acct.query
      user_info.should_not be_nil
    end

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
      info = Misc.whoami(@target, token.auth_header)
      info[:user_name].should == @username
      contents = TokenCoder.decode(token.info[:access_token], nil, nil, false)
      contents[:user_name].should == @username
    end
  end

  context "with an authcode grant," do

    if ENV["UAA_CLIENT_LOGIN"]
      it "should get a uri to be sent to the user agent to initiate autologin" do
        logn = ENV["UAA_CLIENT_LOGIN"]
        toki = TokenIssuer.new(logn, @client_id, @client_secret)
        redir_uri = "http://call.back/uri_path"
        uri_parts = toki.autologin_uri(redir_uri, {username: @username, password: "newpassword"}).split('?')
        uri_parts[0].should == "#{logn}/oauth/authorize"
        params = Util.decode_form_to_hash(uri_parts[1])
        params[:response_type].should == "code"
        params[:client_id].should == @client_id
        params[:scope].should be_nil
        params[:redirect_uri].should == redir_uri
        params[:state].should_not be_nil
        params[:code].should_not be_nil
      end
    end

  end

  context "with a client credentials grant," do

    before :all do
      toki = TokenIssuer.new(@target, @client_id, @client_secret)
      @user_acct = UserAccount.new(@target, toki.client_credentials_grant.auth_header)
    end

    it "deletes the user by name" do
      @user_acct.delete_by_name(@username)
      expect { @user_acct.get_by_name(@username) }.to raise_exception(NotFound)
    end

    it "complains about an attempt to delete a non-existent user" do
      expect { @user_acct.delete_by_name("non-existent-user") }.to raise_exception(NotFound)
    end

  end

end

end
