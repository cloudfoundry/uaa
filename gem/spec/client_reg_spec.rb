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

  before :all do
    @debug = true
    @stub_uaa = StubUAA.new(@debug).run_on_thread
    admin_group = @stub_uaa.scim.add(:group, {display_name: "client_admin"})
    @stub_uaa.scim.add(:group, {display_name: "foo"})
    @stub_uaa.scim.add(:group, {display_name: "bar"})
    @stub_uaa.scim.add(:client, {display_name: "test_client", password: "test_secret",
        authorized_grant_types: ["client_credentials", "authorization_code"],
        groups: [admin_group[:id]], access_token_validity: 60 * 60 * 24 * 7 })
    @issuer = TokenIssuer.new(@stub_uaa.url, "test_client", "test_secret", nil, @debug)
    @token = @issuer.client_credentials_grant
    @client_reg = ClientReg.new(@stub_uaa.url, @token.auth_header, @debug)
    @client_reg.async = @async = false
  end

  after :all do @stub_uaa.stop if @stub_uaa end
  subject { @client_reg }

  def request
    return yield unless @async
    cthred = Thread.current
    EM.schedule { Fiber.new { yield; cthred.run }.resume }
    Thread.stop
  end

  it "should register a client" do
    new_client = { client_id: "new_client", client_secret: "new_client_secret",
      scope: "foo bar", authorized_grant_types: "client_credentials authorization_code",
      access_token_validity: 60 * 60 * 24 * 7 }
    request do
      subject.create(new_client).should be_nil
    end
  end

  it "should get a client registration" do
    request do
      result = subject.get "new_client"
      puts "here", result
      result[:client_id].should == "new_client"
      result[:scope].should include "bar"
      result[:authorized_grant_types].should include "authorization_code"
    end
  end

end

end
