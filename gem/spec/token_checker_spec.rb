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
require 'uaa/token_checker'
require 'webmock_helper'

describe Cloudfoundry::Uaa::TokenChecker do
  include WebMock::API

  subject do
    Cloudfoundry::Uaa::TokenChecker.new("http://localhost:8080/uaa",
        "test_resource", "test_secret")
  end

  before :all do
    WebMock.enable!
    WebMock.reset!
  end

  before :each do
    @stub_req = stub_request(:get, "http://test_resource:test_secret@localhost:8080/uaa/check_token")
        .with(:headers => {'Accept' => 'application/json'},
            :query => {'token' => 'two', 'token_type' => 'one'})
    subject.trace = false
  end

  it "should raise an auth error if the given auth header is bad" do
    @stub_req.to_return(File.new(spec_asset('check_token_success.txt')))
    expect { subject.decode(nil) }.to raise_exception(Cloudfoundry::Uaa::TokenChecker::AuthError)
    expect { subject.decode("one two three") }.to raise_exception(Cloudfoundry::Uaa::TokenChecker::AuthError)
  end

  it "should raise a bad response error if the response is not json" do
    @stub_req.to_return(File.new(spec_asset('text_reply.txt')))
    expect { subject.decode("one two")}.should raise_exception(Cloudfoundry::Uaa::TokenChecker::BadResponse)
  end

  it "should raise a target error if the response is 400 with valid oauth json error" do
    @stub_req.to_return(File.new(spec_asset('oauth_error_reply.txt')))
    expect { subject.decode("one two")}.should raise_exception(Cloudfoundry::Uaa::TokenChecker::TargetError)
  end

  it "should GET decoded token hash from the check_token endpoint" do
    @stub_req.to_return(File.new(spec_asset('check_token_success.txt')))
    info = subject.decode("one two")
    info.should include(:resource_ids)
    info[:resource_ids].should include("test_resource")
    info.should include(:email => "derek@gmail.com")
  end

  it "should raise an auth error if the returned token does not contain the resource id" do
    @stub_req.to_return(File.new(spec_asset('check_token_bad_resource.txt')))
    expect { subject.decode("one two")}.to raise_exception(Cloudfoundry::Uaa::TokenChecker::AuthError)
  end

end
