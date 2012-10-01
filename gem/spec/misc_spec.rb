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

end

end
