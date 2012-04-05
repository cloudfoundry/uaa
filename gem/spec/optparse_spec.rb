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
require 'cli/optparse'

describe "Uaa opts parser" do

  it "should parse empty args" do
    command, args, options, result = CF::UAA::OptParser.parse([])
    command.should be_nil
    args.should be_empty
    options[:verbose].should be_false
    result.should_not be_nil
  end

  it "should exit with non nil status if there is a valid switch but no command" do
    command, args, options, result = CF::UAA::OptParser.parse(["--verbose"])
    command.should be_nil
    args.should be_empty
    options[:verbose].should be_true
    result.should_not be_nil
  end

  it "should accept --trace as an alias for --verbose" do
    command, args, options, result = CF::UAA::OptParser.parse(["--trace"])
    options[:verbose].should be_true
    result.should_not be_nil
  end

  {
    :client_id => "client-id",
    :client_secret => "client-secret"
  }.each do |underscore,hyphen|

    it "should accept #{hyphen} as an alias for #{underscore}" do
      command, args, options, result = CF::UAA::OptParser.parse(["--#{hyphen}", "foo"])
      options[underscore].should be_true
    end

  end

  it "should accept --grant-type as an alias for --grant_type" do
    command, args, options, result = CF::UAA::OptParser.parse(%w[login --grant_type foo])
    options[:grant_type].should be_true
  end

  it "should exit cleanly on -v" do
    command, args, options, result = CF::UAA::OptParser.parse(["-v"])
    result.should_not be_nil
  end

  it "should exit cleanly on -h" do
    command, args, options, result = CF::UAA::OptParser.parse(["-h"])
    result.should_not be_nil
  end

  it "should exit with status=false on illegal switch" do
    command, args, options, result = CF::UAA::OptParser.parse(["-foo"])
    result.should_not be_nil
    result.should be_false
 end

  it "should exit with status=false on illegal command" do
    command, args, options, result = CF::UAA::OptParser.parse(["foo"])
    result.should be_false
  end

  it "should exit cleanly on 'help decode'" do
    command, args, options, result = CF::UAA::OptParser.parse(%w[help decode])
    result.should be_false
  end

  it "should exit cleanly on 'help'" do
    command, args, options, result = CF::UAA::OptParser.parse(["help"])
    result.should be_false
  end

  it "should extract global options" do
    command, args, options, result = CF::UAA::OptParser.parse(%w[--client_id foo login])
    result.should be_true
    options[:client_id].should == "foo"
    command.should == :login
    args.should be_empty
  end

  it "should allow global options after command" do
    pending "fix option ordering"
    command, args, options, result = CF::UAA::OptParser.parse(%w[login --verbose])
    result.should be_true
    options.should == {:verbose=>true}
    command.should == :login
    args.should be_empty
  end

  it "should allow equals sign separator" do
    command, args, options, result = CF::UAA::OptParser.parse(%w[--client_id=foo login])
    result.should be_true
    options[:client_id].should == "foo"
    command.should == :login
    args.should be_empty
  end

  it "should extract command arguments" do
    command, args, options, result = CF::UAA::OptParser.parse(%w[login marissa])
    result.should be_true
    command.should == :login
    args.should == ["marissa"]
  end

  it "should allow login-specific options" do
    command, args, options, result = CF::UAA::OptParser.parse(%w[login --grant_type client_credentials])
    result.should be_true
    options[:grant_type].should == "client_credentials"
    command.should == :login
  end

end
