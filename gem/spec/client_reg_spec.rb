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
require 'uaa/client_reg'
require 'cli/base'
require 'stub_uaa'

module CF::UAA

describe ClientReg do

  include SpecHelper

  before :all do
    #Util.default_logger(:trace)
    id, secret = "testclient", "testsecret"
    @stub_uaa = StubUAA.new(id, secret).run_on_thread
    @token = TokenIssuer.new(@stub_uaa.url, id, secret).client_credentials_grant
    @client_reg = ClientReg.new(@stub_uaa.url, @token.auth_header)
    @client_reg.async = @async = false
  end

  after :all do @stub_uaa.stop if @stub_uaa end
  subject { @client_reg }

  it "should register a client" do
    new_client = { client_id: "new_client", client_secret: "new_client_secret",
      authorities: "password.write openid",
      authorized_grant_types: "client_credentials authorization_code",
      access_token_validity: 60 * 60 * 24 * 7 }
    frequest { subject.create(new_client)}.should be_nil
  end

  it "should get a client registration" do
    result = frequest { subject.get "new_client" }
    result[:client_id].should == "new_client"
    result[:authorities].should include "openid"
    result[:authorized_grant_types].should include "authorization_code"
  end

end

end
