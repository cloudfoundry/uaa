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

require 'set'
require 'spec_helper'
require 'uaa/token_issuer'
require 'stub_uaa'

module CF::UAA

describe TokenIssuer do

  include SpecHelper

  before :all do
    #Util.default_logger(:trace)
    @stub_uaa = StubUAA.new.run_on_thread
    readers = @stub_uaa.scim.add(:group, displayname: "logs.read")
    @stub_uaa.scim.add(:client, client_id: "test_client", client_secret: "test_secret",
        authorized_grant_types: ["client_credentials", "authorization_code",
            "password", "implicit", "refresh_token"],
        authorities: [readers, @stub_uaa.scim.id("scim.read", :group),
            @stub_uaa.scim.id("openid", :group)],
        scope: [@stub_uaa.scim.id("openid", :group), readers],
        access_token_validity: 60 * 60 * 24 * 8 )
    id = @stub_uaa.scim.add(:user, username: "joe+admin", password: "?joe's%password$@ ")
    @stub_uaa.auto_groups.each {|g| @stub_uaa.scim.add_member(g, id)}
    @stub_uaa.scim.add_member(readers, id)
    @issuer = TokenIssuer.new(@stub_uaa.url, "test_client", "test_secret")
    @issuer.async = @async = false
    @state = {}
  end

  after :all do @stub_uaa.stop if @stub_uaa end
  before :each do @stub_uaa.reply_badly = :none end
  subject { @issuer }

  def check_good_token(token, scope, client_id)
    token.should be_an_instance_of Token
    scope = Util.arglist(scope).to_set
    token.info[:access_token].should_not be_nil
    token.info[:token_type].should match /^bearer$/i
    Util.arglist(token.info[:scope]).to_set.should == scope
    token.info[:expires_in].should == 60 * 60 * 24 * 8
    contents = TokenCoder.decode(token.info[:access_token])
    Util.arglist(contents[:scope]).to_set.should == scope
    contents[:jti].should_not be_nil
    contents[:client_id].should == client_id
  end

  context "with client credentials grant" do

    it "should get a token with client credentials" do
      result = frequest { subject.client_credentials_grant("logs.read") }
      check_good_token result, "logs.read", "test_client"
    end

    it "should get all granted scopes if none specified" do
      result = frequest { subject.client_credentials_grant }
      check_good_token result, "logs.read scim.read openid", "test_client"
    end

    it "should raise a bad response error if response content type is not json" do
      @stub_uaa.reply_badly = :non_json
      result = frequest { subject.client_credentials_grant }
      result.should be_an_instance_of BadResponse
    end

    it "should raise a bad response error if the response is not proper json" do
      @stub_uaa.reply_badly = :bad_json
      result = frequest { subject.client_credentials_grant }
      result.should be_an_instance_of BadResponse
    end

    it "should raise a target error if the response is 400 with valid oauth json error" do
      result = frequest { subject.client_credentials_grant("bad.scope") }
      result.should be_an_instance_of TargetError
    end
  end

  context "with owner password grant" do

    it "should get a token with owner password" do
      result = frequest { subject.owner_password_grant("joe+admin", "?joe's%password$@ ", "openid") }
      check_good_token result, "openid", "test_client"
    end

  end

  context "with implicit grant" do

    it "should be able to get the prompts for credentials used to authenticate implicit grant" do
      result = frequest { subject.prompts }
      result.should_not be_empty
    end

    it "should raise a bad target error if no prompts are received" do
      prompts = @stub_uaa.info.delete(:prompts) # remove the prompts temporarily
      result = frequest { subject.prompts }
      @stub_uaa.info[:prompts] = prompts # put them back
      result.should be_an_instance_of BadResponse
    end

    it "should get an access token" do
      result = frequest { subject.implicit_grant_with_creds(username: "joe+admin", password: "?joe's%password$@ ") }
      check_good_token result, "openid logs.read", "test_client"
    end

    it "should reject an access token with wrong state" do
      @stub_uaa.reply_badly = :bad_state
      result = frequest { subject.implicit_grant_with_creds(username: "joe+admin", password: "?joe's%password$@ ") }
      result.should be_an_instance_of BadResponse
    end

    it "should reject an access token with no type" do
      @stub_uaa.reply_badly = :no_token_type
      result = frequest { subject.implicit_grant_with_creds(username: "joe+admin", password: "?joe's%password$@ ") }
      result.should be_an_instance_of BadResponse
    end

  end

  context "with auth code grant" do

    it "should get the authcode uri to be sent to the user agent for an authcode" do
      redir_uri = "http://call.back/uri_path"
      uri_parts = subject.authcode_uri(redir_uri).split('?')
      uri_parts[0].should == "#{@stub_uaa.url}/oauth/authorize"
      params = Util.decode_form_to_hash(uri_parts[1])
      params[:response_type].should == "code"
      params[:client_id].should == "test_client"
      params[:scope].should be_nil
      params[:redirect_uri].should == redir_uri
      params[:state].should_not be_nil
    end

    it "should get an access token with an authorization code" do
      cburi = "http://call.back/uri_path"
      redir_uri = subject.authcode_uri(cburi)
      test_uri = "#{redir_uri}&#{URI.encode_www_form(emphatic_user: 'joe+admin')}"
      status, body, headers = frequest { subject.http_get(test_uri) }
      status.should == 302
      m = %r{^#{Regexp.escape(cburi)}\?(.*)$}.match(headers[:location])
      m.should_not be_nil
      result = frequest { subject.authcode_grant(redir_uri, m[1]) }
      check_good_token result, "openid logs.read", "test_client"
      result.info[:refresh_token].should_not be_nil
      @state[:refresh_token] = result.info[:refresh_token]
    end

    it "should get an access token with a specific scope" do
      cburi = "http://call.back/uri_path"
      redir_uri = subject.authcode_uri(cburi, "logs.read")
      test_uri = "#{redir_uri}&#{URI.encode_www_form(emphatic_user: 'joe+admin')}"
      status, body, headers = frequest { subject.http_get(test_uri) }
      status.should == 302
      m = %r{^#{Regexp.escape(cburi)}\?(.*)$}.match(headers[:location])
      m.should_not be_nil
      result = frequest { subject.authcode_grant(redir_uri, m[1]) }
      check_good_token result, "logs.read", "test_client"
      result.info[:refresh_token].should_not be_nil
      @state[:refresh_token] = result.info[:refresh_token]
    end

    it "should reject an access token with an invalid state" do
      authcode_uri = subject.authcode_uri "http://call.back/uri_path"
      expect { subject.authcode_grant(authcode_uri, "code=good.auth.code&state=invalid-state") }
        .to raise_exception(BadResponse)
    end
  end

  context "with refresh token grant" do

    it "should get an access token with a refresh token" do
      result = frequest { subject.refresh_token_grant(@state[:refresh_token]) }
      check_good_token result, "openid logs.read", "test_client"
    end

    it "should get an access token with specific scope" do
      result = frequest { subject.refresh_token_grant(@state[:refresh_token], "openid") }
      check_good_token result, "openid", "test_client"
    end
  end

end

end
