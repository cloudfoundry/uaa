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
require 'uaa/user_account'
require 'webmock/rspec'

describe Cloudfoundry::Uaa::UserAccount do

  subject { Cloudfoundry::Uaa::UserAccount.new("http://localhost:8080/uaa", 'Bearer example_access_token') }

  before :all do
    WebMock.enable!
    WebMock.reset!
  end

  before :each do
    @stub_create_user_req = stub_request(:post, "http://localhost:8080/uaa/User").
                                          with(:headers => {'Authorization'=>'Bearer example_access_token'})
    @stub_update_password_req = stub_request(:put, "http://localhost:8080/uaa/User/randomId/password").
                                          with(:headers => {'Authorization'=>'Bearer example_access_token'})
    subject.trace = true
  end

  it "should be possible to register a user" do
    @stub_create_user_req.to_return(:status => 200,
                        :body => "{\"id\":\"randomId\", \"email\":\"jdoe@example.org\"}",
                        :headers => {"Content-Type" => "application/json"})
    @stub_update_password_req.to_return(:status => 204)
    result = subject.create("jdoe", "password", "jdoe@example.org", "John", "Doe")
    result[:id].should eql("randomId")
    result[:email].should eql("jdoe@example.org")
  end

  it "should be possible to register a user with multiple email addresses" do
    @stub_create_user_req.to_return(:status => 200,
                        :body => "{\"id\":\"randomId\", \"email\":[\"jdoe@example.org\", \"jdoe@gmail.com\"]}",
                        :headers => {"Content-Type" => "application/json"})
    @stub_update_password_req.to_return(:status => 204)
    result = subject.create("jdoe", "password", ["jdoe@example.org", "jdoe@gmail.com"], "John", "Doe")
    result[:id].should eql("randomId")
    result[:email].sort().should eql(["jdoe@example.org", "jdoe@gmail.com"].sort())
  end

  it "should not be possible to register a user without an access token" do
    subject =  Cloudfoundry::Uaa::UserAccount.new("http://localhost:8080/uaa", nil)
    expect { subject.create("jdoe", "password", "jdoe@example.org", nil) }
        .to raise_exception(Cloudfoundry::Uaa::UserAccount::AuthError)
  end
end
