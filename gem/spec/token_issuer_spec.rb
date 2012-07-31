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
    readers = @stub_uaa.scim.add(:group, {displayname: "logs.read"})
    @stub_uaa.scim.add(:client, {displayname: "test_client", password: "test_secret",
        authorized_grant_types: ["client_credentials", "authorization_code"],
        groups: [readers[:id], @stub_uaa.scim.name_to_id("scim.read"),
            @stub_uaa.scim.name_to_id("openid")],
        access_token_validity: 60 * 60 * 24 * 8 })
    @stub_uaa.scim.add(:user, {username: "joe+admin", password: "?joe's%password$@ ",
        groups: [@stub_uaa.scim.name_to_id("openid")]})
    @issuer = TokenIssuer.new(@stub_uaa.url, "test_client", "test_secret")
    @issuer.async = @async = false
  end

  after :all do @stub_uaa.stop if @stub_uaa end
  subject { @issuer }
  before :each do @stub_uaa.reply_badly = :none end

  def check_good_token(token, scope, client_id)
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

=begin

  context "with refresh token grant" do

    it "should get an access token with a refresh token" do
      @refresh_token = "refresher286432"
      StubServer.responder do |request, reply|
        request.path.should == '/oauth/token'
        request.headers[:authorization].should == Http.basic_auth("test_app", "test_secret")
        request.headers[:content_type].should == "application/x-www-form-urlencoded"
        request.headers[:accept].should == "application/json"
        request.body.should == URI.encode_www_form({grant_type: 'refresh_token', refresh_token: @refresh_token, scope: 'read'})
        reply.headers[:content_type] = "application/json"
        reply.body = good_token_info.to_json
        reply
      end
      StubServer.request { check_good_token = subject.refresh_token_grant(@refresh_token) }
    end
  end

  context "with implicit grant" do

    it "should be able to get the prompts for credentials used to authenticate implicit grant" do
      StubServer.responder do |request, reply|
        request.headers[:authorization].should be_nil
        request.headers[:accept].should =~ /application\/json/
        request.method.should == :get
        request.path.should == "/login"
        reply.headers[:content_type] = "application/json;charset=UTF-8"
        reply.body = %<{"prompts":{"hat_size": ["text", "Hat Size"],
            "fav-color": ["password", "Secret Favorite Color"],
            "something longer with spaces ": ["text", "Prompt for something longer with spaces"]},
            "other json info": ["perhaps", "an", "array"]}>
        reply
      end
      StubServer.request do
        subject.prompts.should_not be_empty
        #puts subject.prompts # TODO: some better checks for valid prompts here?
      end
    end

    it "should raise a bad target error if no prompts are received" do
      StubServer.responder do |request, reply|
        reply.headers[:content_type] = "application/json;charset=UTF-8"
        reply.body = %<{"nonprompts":{"hat_size": ["text", "Hat Size"]},
            "other json info": ["perhaps", "an", "array"]}>
        reply
      end
      StubServer.request { expect { subject.prompts}.to raise_exception(BadResponse) }
    end


    it "should get an access token" do
      StubServer.responder do |request, reply|
        request.method.should == :post
        request.headers[:content_type].should == "application/x-www-form-urlencoded"
        # request.body.should == URI.encode_www_form(credentials: {username: 'joe', password: 'joes password'}.to_json)
        request.body.should == "credentials=#{URI.encode({username: 'joe', password: 'joes password'}.to_json)}"
        request.path.should =~ %r{^/oauth/authorize\?}
        qparams = Util.decode_form_to_hash(URI.parse(request.path).query)
        qparams[:response_type].should == "token"
        qparams[:client_id].should == "test_app"
        qparams[:scope].should == "read"
        #qparams[:redirect_uri].should == redirect_uri # test for this
        qparams[:state].should_not be_nil
        rparams = {access_token: "good.access.token", token_type: "TokTypE",
            expires_in: 3, scope: "read-logs", state: qparams[:state]}
        reply.status = 302
        reply.headers[:location] = "http://uaa.cloudfoundry.com/redirect/test_app##{URI.encode_www_form(rparams)}"
        reply
      end
      StubServer.request do
        token = subject.implicit_grant_with_creds(username: "joe", password: "joes password")
        token.auth_header.should == "TokTypE good.access.token"
        token.info[:access_token].should == "good.access.token"
        token.info[:token_type].should == "TokTypE"
        token.info[:scope].should == "read-logs"
        token.info[:expires_in].should == "3"
      end
    end

    it "should reject an access token with wrong state" do
      StubServer.responder do |request, reply|
        rparams = {access_token: "good.access.token", token_type: "TokTypE",
            expires_in: 3, scope: "read-logs", state: "invalid_state"}
        reply.status = 302
        reply.headers[:location] = "http://uaa.cloudfoundry.com/redirect/test_app##{URI.encode_www_form(rparams)}"
        reply
      end
      StubServer.request do
        expect { subject.implicit_grant_with_creds(username: "joe", password: "joes password") }
            .to raise_exception(BadResponse)
      end
    end

    it "should reject an access token with no type" do
      StubServer.responder do |request, reply|
        qparams = Util.decode_form_to_hash(URI.parse(request.path).query)
        rparams = {access_token: "good.access.token", expires_in: 3, scope: "read-logs", state: qparams[:state]}
        reply.status = 302
        reply.headers[:location] = "http://uaa.cloudfoundry.com/redirect/test_app##{URI.encode_www_form(rparams)}"
        reply
      end
      StubServer.request do
        expect { subject.implicit_grant_with_creds(username: "joe", password: "joes password") }
            .to raise_exception(BadResponse)
      end
    end

  end

  context "with auth code grant" do

    it "should get the authcode uri to be sent to the user agent for an authcode" do
      redir_uri = "http://call.back/uri_path"
      uri_parts = subject.authcode_uri(redir_uri).split('?')
      uri_parts[0].should == "#{StubServer.url}/oauth/authorize"
      params = Util.decode_form_to_hash(uri_parts[1])
      params[:response_type].should == "code"
      params[:client_id].should == "test_app"
      params[:scope].should == "read"
      params[:redirect_uri].should == redir_uri
      params[:state].should_not be_nil
    end

    it "should get an access token with an authcode" do
      @redir_uri = "http://call.back/uri_path"
      StubServer.responder do |request, reply|
        request.path.should == '/oauth/token'
        request.headers[:authorization].should == Http.basic_auth("test_app", "test_secret")
        request.headers[:content_type].should == "application/x-www-form-urlencoded"
        request.headers[:accept].should == "application/json"
        request.body.should == URI.encode_www_form(
             {grant_type: "authorization_code", code: "good.auth.code",
            redirect_uri: @redir_uri, scope: "read"})
        reply.headers[:content_type] = "application/json"
        reply.body = good_token_info.to_json
        reply
      end
      StubServer.request do
        authcode_uri = subject.authcode_uri(@redir_uri)
        params = Util.decode_form_to_hash(URI.parse(authcode_uri).query)
        check_good_token subject.authcode_grant(authcode_uri, "code=good.auth.code&state=#{params[:state]}")
      end
    end

    it "should reject an access token with an invalid state" do
      authcode_uri = subject.authcode_uri "http://call.back/uri_path"
      expect { subject.authcode_grant(authcode_uri, "code=good.auth.code&state=invalid-state") }
        .to raise_exception(BadResponse)
    end
  end

=end

end

end
