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
require 'uaa/id_token'

module CF::UAA

describe IdToken do

  subject { IdToken.new("http://localhost:8080/uaa", "test token") }

  before :each do
    subject.debug = false
  end

  it "should do something" do
    subject.debug.should_not be_nil
  end

end

end
