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
require 'uaa/client'

describe Cloudfoundry::Uaa::UserAccount do

  subject { Cloudfoundry::Uaa::UserAccount.new("http://localhost:8080/uaa", nil) }

  before :each do
    client = Cloudfoundry::Uaa::Client.new()
    if !integration_test?
      subject.stub!(:perform_http_request) do |req|
        @input = req
        @response
      end
      client.stub!(:perform_http_request) do |req|
        @input = req
        @response
      end
    end
    subject.trace = true
    @response = [200, '{"access_token":"example_access_token"}', nil]
    client.target = "http://localhost:8080/uaa"
    client.client_id = "my"
    client.client_secret = "myclientsecret"
    client.grant_type = "client_credentials"
    @token = client.login() if @token.nil?
    subject.access_token = @token
  end

  it "should be possible to register a user", :integration=>false do
    @response = [200, '{"id":"randomId","email":"jdoe@example.org"}', nil]
    result = subject.create("jdoe", "password", "jdoe@example.org", {:family_name=>"Doe", :given_name=>"John"})
    result[:id].should eql("randomId")
    result[:email].should eql("jdoe@example.org")
  end

  it "should not be possible to register a user without an access token", :integration=>false do
    subject.access_token = nil
    expect do
      result = subject.create("jdoe", "password", "jdoe@example.org", nil)
    end.should raise_exception(Cloudfoundry::Uaa::UserAccount::AuthError)
  end

end
