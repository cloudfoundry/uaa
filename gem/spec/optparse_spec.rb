require 'spec_helper'
require 'cli/optparse'

describe "Uaa opts parser" do

  it "should parse empty args" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse([])
    command.should be_nil
    args.should be_empty
    options[:verbose].should be_false
    result.should_not be_nil
  end

  it "should exit with non nil status if there is a valid switch but no command" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(["--verbose"])
    command.should be_nil
    args.should be_empty
    options[:verbose].should be_true
    result.should_not be_nil
  end

  it "should exit cleanly on -v" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(["-v"])
    result.should_not be_nil
  end

  it "should exit cleanly on -h" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(["-h"])
    result.should_not be_nil
  end

  it "should exit with status=false on illegal switch" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(["-foo"])
    result.should_not be_nil
    result.should be_false
 end

  it "should exit with status=false on illegal command" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(["foo"])
    result.should be_false
  end

  it "should exit cleanly on 'help decode'" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(%w[help decode])
    result.should be_false
  end

  it "should exit cleanly on 'help'" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(["help"])
    result.should be_false
  end

  it "should extract global options" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(%w[--client_id foo login])
    result.should be_true
    options[:client_id].should == "foo"
    command.should == :login
    args.should be_empty
  end

  it "should allow global options after command" do
    pending "fix option ordering"
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(%w[login --verbose])
    result.should be_true
    options.should == {:verbose=>true}
    command.should == :login
    args.should be_empty
  end

  it "should allow equals sign separator" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(%w[--client_id=foo login])
    result.should be_true
    options[:client_id].should == "foo"
    command.should == :login
    args.should be_empty
  end

  it "should extract command arguments" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(%w[login marissa])
    result.should be_true
    command.should == :login
    args.should == ["marissa"]
  end

  it "should allow login-specific options" do
    command, args, options, result = Cloudfoundry::Uaa::OptParser.parse(%w[login --grant_type client_credentials])
    result.should be_true
    options[:grant_type].should == "client_credentials"
    command.should == :login
  end

end
