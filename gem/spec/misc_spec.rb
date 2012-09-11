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
require 'uaa/misc'
require 'stub_uaa'

module CF::UAA

describe Misc do

  include SpecHelper

  before :all do @stub_uaa = StubUAA.new.run_on_thread end
  after :all do @stub_uaa.stop if @stub_uaa end

  it "should get the server info" do
    result = frequest { Misc.server(@stub_uaa.url) }
    result[:prompts].should_not be_nil
    result[:token_endpoint].should be_nil
    result[:commit_id].should_not be_nil
  end

  it "should get token_endpoint" do
    @stub_uaa.info[:token_endpoint] = te = "http://alternate/token/end/point"
    result = frequest { Misc.server(@stub_uaa.url) }
    result[:token_endpoint].should == te
  end

  it "should get token validation key" do
    result = frequest { Misc.validation_key(@stub_uaa.url) }
    result[:alg].should_not be_nil
    result[:value].should_not be_nil
  end

=begin

  it "should raise an auth error if the given auth header is bad" do
    expect { subject.decode(nil) }.to raise_exception(AuthError)
    expect { subject.decode("one two three") }.to raise_exception(AuthError)
  end

  it "should raise a bad response error if the response is not json" do
    StubServer.responder do |request, reply|
      reply.headers[:content_type] = "text/plain"
      reply.body = "this is not json"
      reply
    end
    StubServer.request do
      expect { subject.decode("TestTokType TestToken")}.should raise_exception(BadResponse)
    end
  end

  it "should raise a target error if the response is 400 with valid oauth json error" do
    StubServer.responder do |request, reply|
      reply.headers[:content_type] = "application/json"
      reply.body = %<{"error": "invalid_scope",
          "error_description":"description of invalid_scope",
          "error_uri":"http://error.example.com"}>
      reply.status = 400
      reply
    end
    StubServer.request do
      expect { subject.decode("one two")}.should raise_exception(TargetError)
    end
  end

  it "should GET decoded token hash from the check_token endpoint" do
    StubServer.responder do |request, reply|
      request.path.should == "/check_token?token_type=TestTokType&token=TestToken"
      reply.headers[:content_type] = "application/json"
      reply.body = %<{"resource_ids": ["one_resource", "test_resource", "other_resource"],"email":"derek@gmail.com"}>
      reply
    end
    StubServer.request do
      info = subject.decode("TestTokType TestToken")
      info.should include(:resource_ids)
      info[:resource_ids].should include("test_resource")
      info.should include(:email => "derek@gmail.com")
    end
  end

  it "should raise an auth error if the returned token does not contain the audience" do
    StubServer.responder do |request, reply|
      request.path.should == "/check_token?token_type=TestTokType&token=TestToken"
      reply.headers[:content_type] = "application/json"
      reply.body = %<{"aud": ["one_resource", "two_resource", "other_resource"],"email":"derek@gmail.com"}>
      reply
    end
    StubServer.request do
      expect { subject.decode("TestTokType TestToken")}.to raise_exception(AuthError)
    end
  end

=end

end

end
