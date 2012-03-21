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
require 'uaa/token_issuer'
require 'webmock_helper'

describe Cloudfoundry::Uaa::TokenIssuer do
  include WebMock::API

  subject do
    Cloudfoundry::Uaa::TokenIssuer.new("http://localhost:8080/uaa", "test_app",
        "test_secret", "read", "test_resource")
  end

  before :all do
    WebMock.enable!
    WebMock.reset!
  end

  def check_good_token_info(auth_header)
    auth_header.should == "exampletokentype good.access.token"
    subject.info[:access_token].should == "good.access.token"
    subject.info[:token_type].should == "exampletokentype"
    subject.info[:refresh_token].should == "good.refresh.token"
    subject.info[:example_parameter].should == "example parameter value"
    subject.info[:scope].should == "read-logs"
  end

  context "with client credentials grant" do

    before :each do
      @stub_req = stub_request(:post, "http://test_app:test_secret@localhost:8080/uaa/oauth/token")
          .with(headers: {accept: 'application/json', content_type: 'application/x-www-form-urlencoded'},
                body: {grant_type: 'client_credentials', scope: 'read'})
      subject.trace = true
    end

    it "should get a token with client credentials" do
      @stub_req.to_return(File.new(spec_asset('oauth_token_good.txt')))
      check_good_token_info subject.client_credentials_grant
    end

    it "should raise a bad target error if response content type is not json" do
      @stub_req.to_return(File.new(spec_asset('text_reply.txt')))
      expect { subject.client_credentials_grant }.should raise_exception(Cloudfoundry::Uaa::TokenIssuer::BadTarget)
    end

    it "should raise a bad response error if the response is not proper json" do
      @stub_req.to_return(File.new(spec_asset('bad_json_reply.txt')))
      expect { subject.client_credentials_grant }.should raise_exception(Cloudfoundry::Uaa::TokenIssuer::BadResponse)
    end

    it "should raise a bad target error if the http response is bad" do
      @stub_req.to_raise(Net::HTTPBadResponse)
      expect { subject.client_credentials_grant }.should raise_exception(Cloudfoundry::Uaa::TokenIssuer::BadTarget)
    end

    it "should raise a bad target error if the target uri is bad" do
      ti = Cloudfoundry::Uaa::TokenIssuer.new("bad://u**R**_l:8080/uaa", "a", "b", "c", "d")
      ti.trace = true
      expect { ti.client_credentials_grant }.should raise_exception(Cloudfoundry::Uaa::TokenIssuer::BadTarget)
    end

    it "should raise a bad target error if the target uri is nil" do
      ti = Cloudfoundry::Uaa::TokenIssuer.new(nil, "a", "b", "c", "d")
      ti.trace = true
      expect { ti.client_credentials_grant }.should raise_exception(Cloudfoundry::Uaa::TokenIssuer::BadTarget)
    end

    it "should raise an HTTPException if there are rest client errors" do
      @stub_req.to_raise(RestClient::ServerBrokeConnection)
      expect { subject.client_credentials_grant }.should raise_exception(Cloudfoundry::Uaa::TokenIssuer::HTTPException)
    end

    it "should raise a target error if the response is 400 with valid oauth json error" do
      @stub_req.to_return(File.new(spec_asset('oauth_error_reply.txt')))
      expect { subject.client_credentials_grant }.should raise_exception(Cloudfoundry::Uaa::TokenIssuer::TargetError)
    end

    it "should include oauth error info in TargetError" do
      @stub_req.to_return(File.new(spec_asset('oauth_error_reply.txt')))
      begin
        subject.client_credentials_grant
        true.should be_false #force error if exception not raised
      rescue Cloudfoundry::Uaa::TokenIssuer::TargetError => e
        e.info[:error].should == "invalid_scope"
        e.info[:error_description].should == "description of invalid_scope"
        e.info[:error_uri].should == "http://error.example.com"
      end
    end

  end

  context "with owner password grant" do

    before :each do
      @username = "joe_user"
      @userpwd = "?joe's%password$@ "
      @stub_req = stub_request(:post, "http://test_app:test_secret@localhost:8080/uaa/oauth/token")
          .with(headers: {accept: 'application/json', content_type: 'application/x-www-form-urlencoded'},
                body: {grant_type: 'password', username: @username, password: @userpwd, scope: 'read'})
      subject.trace = true
    end

    it "should get a token with owner password" do
      @stub_req.to_return(File.new(spec_asset('oauth_token_good.txt')))
      check_good_token_info subject.owner_password_grant(@username, @userpwd)
    end

    it "should raise a response content type is not json" do
      @stub_req.to_return(File.new(spec_asset('text_reply.txt')))
      expect { subject.owner_password_grant(@username, @userpwd)}.should raise_exception(Cloudfoundry::Uaa::TokenIssuer::BadTarget)
    end

    it "should raise a bad response error if the response is not proper json" do
      @stub_req.to_return(File.new(spec_asset('bad_json_reply.txt')))
      expect { subject.owner_password_grant(@username, @userpwd)}.should raise_exception(Cloudfoundry::Uaa::TokenIssuer::BadResponse)
    end

    it "should raise a target error if the response is 400 with valid oauth json error" do
      @stub_req.to_return(File.new(spec_asset('oauth_error_reply.txt')))
      expect { subject.owner_password_grant(@username, @userpwd)}.should raise_exception(Cloudfoundry::Uaa::TokenIssuer::TargetError)
    end

  end

  context "with refresh token grant" do

    before :each do
      @refresh_token = "slkjdhlsahflawoieuoiwuoiwuero*&^%$\#@!?><\":\';  !\`=\\/"
      @stub_req = stub_request(:post, "http://test_app:test_secret@localhost:8080/uaa/oauth/token")
          .with(headers: {accept: 'application/json', content_type: 'application/x-www-form-urlencoded'},
                body: {grant_type: 'refresh_token', refresh_token: @refresh_token, scope: 'read'})
      subject.trace = true
    end

    it "should get an access token with a refresh token" do
      @stub_req.to_return(File.new(spec_asset('oauth_token_good.txt')))
      check_good_token_info subject.refresh_token_grant(@refresh_token)
    end
  end

  context "with implicit grant" do

    before :each do
      subject.trace = true
    end

    it "should be able to get the prompts for credentials used to authenticate implicit grant" do
      @stub_req = stub_request(:get, "http://localhost:8080/uaa/login")
          .with(headers: {accept: 'application/json'})
          .to_return(File.new(spec_asset('login_info.txt')))
      subject.prompts.should_not be_empty
    end

    it "should raise a bad target error if no prompts are received" do
      @stub_req = stub_request(:get, "http://localhost:8080/uaa/login")
          .with(headers: {accept: 'application/json'})
          .to_return(File.new(spec_asset('login_info_bad.txt')))
      expect { subject.prompts}.to raise_exception(Cloudfoundry::Uaa::TokenIssuer::BadTarget)
    end


    it "should get an access token with credentials via an implicit grant" do
      @stub_req = stub_request(:post, /^http:\/\/localhost:8080\/uaa\/oauth\/authorize.*/ )
          .with(body: {credentials: {username: "joe", password: "joe's password"}.to_json})
          .to_return do |req|
        redirect_uri = "http://uaa.cloudfoundry.com/redirect/test_app"
        params = subject.class.decode_oauth_parameters(URI.parse(req.uri).query)
        params[:response_type].should == "token"
        params[:client_id].should == "test_app"
        params[:scope].should == "read"
        params[:redirect_uri].should == redirect_uri
        params[:state].should_not be_nil
        resp = {access_token: "good.access.token", token_type: "TokTypE",
            expires_in: 3, scope: "read", state: params[:state]}
        loc = "#{redirect_uri}#" + URI.encode_www_form(resp)
        { headers: {"Location" => loc}, status: 302 }
      end
      subject.implicit_grant(username: "joe", password: "joe's password")
          .should == "TokTypE good.access.token"
    end

    it "should reject an access token with wrong state" do
      @stub_req = stub_request(:post, /^http:\/\/localhost:8080\/uaa\/oauth\/authorize.*/ )
          .to_return do |req|
        redirect_uri = "http://uaa.cloudfoundry.com/redirect/test_app"
        resp = {access_token: "good.access.token", token_type: "TokTypE",
            expires_in: 3, scope: "read", state: "not-a-uuid"}
        loc = "#{redirect_uri}#" + URI.encode_www_form(resp)
        { headers: {"Location" => loc}, status: 302 }
      end
      expect { subject.implicit_grant(username: "n/a", password: "n/a") }
          .to raise_exception(Cloudfoundry::Uaa::TokenIssuer::BadResponse)
    end

    it "should reject an access token with no type" do
      @stub_req = stub_request(:post, /^http:\/\/localhost:8080\/uaa\/oauth\/authorize.*/ )
          .to_return do |req|
        redirect_uri = "http://uaa.cloudfoundry.com/redirect/test_app"
        params = subject.class.decode_oauth_parameters(URI.parse(req.uri).query)
        resp = {access_token: "good.access.token",
            expires_in: 3, scope: "read", state: params[:state]}
        loc = "#{redirect_uri}#" + URI.encode_www_form(resp)
        { headers: {"Location" => loc}, status: 302 }
      end
      expect { subject.implicit_grant(username: "n/a", password: "n/a") }
          .to raise_exception(Cloudfoundry::Uaa::TokenIssuer::TargetError)
    end

  end

  context "with auth code grant" do

    before :each do
      subject.trace = true
    end

    it "should raise an ArgumentError if an authcode grant is attempted without first getting the redirect uri" do
      expect {subject.authcode_grant("http://call.back/uri?access_token=here")}
        .to raise_exception(ArgumentError)
    end

    it "should get the redirect uri to send the user agent for an authcode" do
      callback_uri = "http://call.back/uri_path"
      uri = subject.authcode_redirect_uri(callback_uri).split('?')
      uri[0].should == "http://localhost:8080/uaa/oauth/authorize"
      params = subject.class.decode_oauth_parameters(uri[1])
      params[:response_type].should == "code"
      params[:client_id].should == "test_app"
      params[:scope].should == "read"
      params[:redirect_uri].should == callback_uri
      params[:state].should_not be_nil
    end

    it "should get an access token with an authcode" do
      callback_uri = "http://call.back/uri_path"
      @stub_req = stub_request(:post, "http://test_app:test_secret@localhost:8080/uaa/oauth/token")
          .with(headers: {accept: 'application/json', content_type: 'application/x-www-form-urlencoded'},
                body: {grant_type: 'authorization_code', code: "good.auth.code",
                redirect_uri: callback_uri, scope: 'read'})
          .to_return(File.new(spec_asset('oauth_token_good.txt')))

      authcode_uri = subject.authcode_redirect_uri(callback_uri)
      params = subject.class.decode_oauth_parameters(URI.parse(authcode_uri).query)
      check_good_token_info subject.authcode_grant("code=good.auth.code&state=#{params[:state]}")
    end

    it "should reject an access token with an invalid state" do
      callback_uri = "http://call.back/uri_path"
      @stub_req = stub_request(:post, "http://test_app:test_secret@localhost:8080/uaa/oauth/token")
          .with(headers: {accept: 'application/json', content_type: 'application/x-www-form-urlencoded'},
                body: {grant_type: 'authorization_code', code: "good.auth.code",
                redirect_uri: callback_uri, scope: 'read'})
          .to_return(File.new(spec_asset('oauth_token_good.txt')))

      authcode_uri = subject.authcode_redirect_uri(callback_uri)
      params = subject.class.decode_oauth_parameters(URI.parse(authcode_uri).query)
      expect { subject.authcode_grant("code=good.auth.code&state=non-uuid-state") }
        .to raise_exception(Cloudfoundry::Uaa::TokenIssuer::BadResponse)
    end
  end

end
