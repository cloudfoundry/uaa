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
require 'uaa/token_issuer'

describe Cloudfoundry::Uaa::TokenIssuer do

  subject do
    Cloudfoundry::Uaa::TokenIssuer.new("http://localhost:8080/uaa", "test_app",
        "test_secret", "read", "test_resource")
  end

  before :each do
    if !integration_test?
      subject.stub!(:perform_http_request) do |req|
        @input = req
        @response
      end
    end
    subject.trace = true
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
    @response = [200, '{"prompts":{"username":["text", "Username"], "password":["password", "Password"]}}', {:content_type => "application/json"}]
    subject.prompts.should_not be_empty
  end

  context "with client_credentials grant" do

    before :each do
      @response = [200, '{"access_token":"FOO"}', {:content_type => "application/json"}]
    end

    it "should get a token with client credentials", :integration=>false do
      expect do
        subject.client_credentials_grant
        @input[:url].should =~ /\/token/
      end.should_not raise_exception
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
        @response = [200, '{"access_token":"FOO"}', {:content_type => "application/json"}]
      end

      it "should post to the token endpoint", :integration=>false do
        subject.owner_password_grant(@username, @password)
        @input[:url].should =~ /\/token/
        @input[:method].should == :post
      end

      it "should include the grant type", :integration=>false do
        subject.owner_password_grant(@username, @password)
        @input[:payload].should =~ /grant_type=password/
      end

      it "should not have a redirect uri", :integration=>false do
        subject.owner_password_grant(@username, @password)
        @input[:payload].should_not =~ /redirect_uri=/
      end

      it "should be able to login, obtaining an access token, given a username and password", :integration=>true do
        token = subject.owner_password_grant(@username, @password)
        token.should_not be_nil
      end
    end
  end
end
