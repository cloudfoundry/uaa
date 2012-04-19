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

describe CF::UAA::Client do

  before :each do
    if !integration_test?
      subject.stub!(:perform_http_request) do |req|
        @input = req
        @response
      end
    end
    subject.target = "http://localhost:8080/uaa"
    subject.trace = false
    subject.async = false
    @username = "marissa"
    @password = "koala"
  end

  it "should raise an error if it can't get prompts from the server", :integration=>false do
    @response = [404, nil, nil]
    expect { subject.prompts }.should raise_exception(Exception)
  end

  it "should raise an error if it http GET throws exception", :integration=>false do
    subject.stub!(:json_get).and_raise(StandardError)
    expect { subject.prompts }.should raise_exception(Exception)
  end

  it "should be able to get the prompts from the server", :integration=>true do
    @response = [200, '{"prompts":{"username":["text", "Username"], "password":["password", "Password"]}}', nil]
    subject.prompts.should_not be_empty
  end

  context "with client_credentials grant" do

    before :each do
      @response = [200, '{"access_token":"FOO"}', nil]
    end

    it "should not require prompts", :integration=>false do
      expect do
        subject.login(:client_id=>"app", :client_secret=>"appclientsecret", :grant_type=>"client_credentials")
        @input[:url].should =~ /\/token/
      end.should_not raise_exception(CF::UAA::PromptRequiredError)
    end

  end

  context "when logging in with username and password" do

    before :each do
      if !integration_test?
        subject.stub!(:prompts).and_return({:username=>["text", "Username"], :password=>["password", "Password"]})
      end
    end


    context "with password grant" do

      before :each do
        @response = [200, '{"access_token":"FOO"}', nil]
      end

      it "should require prompts if password missing", :integration=>false do
        expect do
          subject.login(:username=>@username, :grant_type=>"password")
        end.should raise_exception(CF::UAA::PromptRequiredError)
      end

      it "should require prompts if username and password missing", :integration=>false do
        expect do
          subject.login(:grant_type=>"password")
        end.should raise_exception(CF::UAA::PromptRequiredError)
      end

      it "should post to the token endpoint", :integration=>false do
        subject.login(:username=>@username, :password=>@password, :client_id=>"foo", :grant_type=>"password")
        @input[:url].should =~ /\/token/
        @input[:method].should == :post
      end

      it "should include the grant type", :integration=>false do
        subject.login(:username=>@username, :password=>@password, :client_id=>"foo", :grant_type=>"password")
        @input[:payload].should =~ /grant_type=password/
      end

      it "should not have a redirect uri", :integration=>false do
        subject.login(:username=>@username, :password=>@password, :grant_type=>"password")
        @input[:payload].should_not =~ /redirect_uri=/
      end

      it "should be able to login, obtaining an access token, given a username and password", :integration=>true do
        token = subject.login(:username=>@username, :password=>@password, :grant_type=>"password", :client_id=>"app", :client_secret=>"appclientsecret")
        token.should_not be_nil
      end

      it "should use the client id if provided", :integration=>false do
        subject.login(:username=>@username, :password=>@password, :client_id=>"foo", :grant_type=>"password")
        @input[:payload].should =~ /client_id=foo/
        @input[:headers]['Authorization'].should_not == @default_auth if @default_auth
      end

      it "should use not send the client secret in form data", :integration=>false do
        token = subject.login(:username=>@username, :password=>@password, :grant_type=>"password")
        @input[:payload].should_not =~ /client_secret=/
      end

      it "should concatenate scope parameters in the HTTP post", :integration=>false do
        token = subject.login(:username=>@username, :password=>@password, :scope=>["read","write"], :grant_type=>"password")
        @input[:payload].should =~ /scope=read write/
        @default_auth = @input[:headers]['Authorization']
      end

      it "should add basic auth", :integration=>false do
        token = subject.login(:username=>@username, :password=>@password, :grant_type=>"password")
        @input[:headers]['Authorization'].should =~ /Basic .*/
      end

      it "should not send credentials hash", :integration=>false do
        token = subject.login(:username=>@username, :password=>@password, :grant_type=>"password")
        @input[:payload].should_not =~ /credentials:.*/
      end

      it "should send credentials in form", :integration=>false do
        token = subject.login(:username=>@username, :password=>@password, :grant_type=>"password")
        @input[:payload].should =~ /username=#{@username}.*/
      end

    end

    context "with implicit grant" do

      before :each do
        @response = [302, nil, {'Location'=>'urn:oauth:implicit#expires_in=100&access_token=FOO&scope=read'}]
      end

      it "should require prompts if password missing", :integration=>false do
        expect do
          subject.login(:username=>@username)
        end.should raise_exception(CF::UAA::PromptRequiredError)
      end

      it "should require prompts if username and password missing", :integration=>false do
        expect do
          subject.login()
        end.should raise_exception(CF::UAA::PromptRequiredError)
      end

      it "should post to the authorize endpoint", :integration=>false do
        token = subject.login(:username=>@username, :password=>@password)
        @input[:url].should =~ /\/authorize/
        @input[:method].should == :post
      end

      it "should convert credentials to json", :integration=>false do
        token = subject.login(:username=>@username, :password=>@password)
        @input[:payload].should =~ /credentials={"/
      end

      it "should have a redirect uri", :integration=>false do
        token = subject.login(:credentials=>{:username=>@username, :password=>@password})
        @input[:payload].should =~ /redirect_uri=/
      end

      it "should jsonise a hash in the form data", :integration=>false do
        token = subject.login(:credentials=>{:username=>@username, :password=>@password})
        @input[:payload].should =~ /credentials={"username":"#{@username}"/
      end

      it "should be able to login, obtaining an access token, given credentials", :integration=>true do
        token = subject.login(:credentials=>{:username=>@username, :password=>@password})
        token.should_not be_nil
      end

    end

  end

  context "when the token is a JWT" do

    it "should be able to decode explicit token", :integration=>false do
      result = subject.decode_jwt_token(CF::UAA::TokenCoder.encode({foo:"bar"}, "secret"), :token_key=>"secret")
      result.should_not be_nil
      result[:foo].should == "bar"
    end

    it "should be able to decode token by default", :integration=>false do
      result = subject.decode_token(CF::UAA::TokenCoder.encode({foo:"bar"}, "secret"), :token_key=>"secret")
      result.should_not be_nil
      result[:foo].should == "bar"
    end

    it "should fall back to assuming an opaque token", :integration=>true do
      @response = [200, %Q({"user_id":"#{@username}","client_id":"app"}), nil]
      result = subject.decode_token(@token)
      result.should_not be_nil
      result[:user_id].should == @username
    end

   end

  context "once logged in with password grant" do

    before :each do
      @response = [200, '{"access_token":"FOO"}', nil]
      subject.client_id = "app"
      subject.client_secret = "appclientsecret"
      subject.grant_type = "password"
      @token = subject.login(:username=>@username, :password=>@password) if @token.nil?
    end

    it "should be able to decode explicit token", :integration=>true do
      @response = [200, %Q({"user_id":"#{@username}","client_id":"app"}), nil]
      result = subject.decode_token(@token)
      result.should_not be_nil
      result[:user_id].should == @username
    end

    it "should be able to decode its own token", :integration=>true do
      @response = [200, %Q({"user_id":"#{@username}","client_id":"app"}), nil]
      subject.token = @token
      result = subject.decode_token()
      result.should_not be_nil
      result[:user_id].should == @username
    end

    it "should use the client_id if provided", :integration=>false do
      @response = [200, %Q({"user_id":"#{@username}","client_id":"foo"}), nil]
      result = subject.decode_token(@token, :client_id=>"foo")
      @input[:headers]['Authorization'].should_not == @default_auth if @default_auth
    end

  end

  context "once logged in with client credentials grant" do

    before :each do
      @response = [200, '{"access_token":"FOO"}', nil]
      subject.client_id = "my"
      subject.client_secret = "myclientsecret"
      subject.grant_type = "client_credentials"
      @token = subject.login() if @token.nil?
      subject.token = "FOO"
    end

    it "should be able to decode token info", :integration=>true do
      @response = [200, %Q({"client_id":"my"}), nil]
      result = subject.decode_token(@token)
      result.should_not be_nil
      result[:user_id].should be_nil
      result[:client_id].should == "my"
    end

    it "should require an access token register a user", :integration=>false do
      subject.token = nil
      expect do
        result = subject.register("bar")
      end.should raise_exception(StandardError)
    end

    it "should require prompts to register a user", :integration=>false do
      expect do
        result = subject.register(:username=>"bar")
      end.should raise_exception(CF::UAA::PromptRequiredError)
    end

    it "should be able to register a user", :integration=>false do
      @response = [200, '{"id":"BAR","email":"bar@test.org"}', nil]
      result = subject.register(:username=>"bar", :password=>"password", :email=>"bar@test.org", :family_name=>"Bloggs", :given_name=>"Bar")
      result[:id].should == "BAR"
    end

  end

end
