require 'spec_helper'

describe "Uaa cli dispatcher" do

  before :each do
    @client = mock(Cloudfoundry::Uaa::Client)
    @client.stub!(:target=)
  end

  it "should set the trace flag on the client when verbose option is set" do
    dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client)
    @client.should_receive(:trace=)
    begin
      dispatcher.dispatch(:foo, [], {:verbose=>true})
    rescue StandardError
    end
  end

  context "when target file is customized" do

    before :all do
      Dir.mkdir "/tmp" unless Dir.exist? "/tmp"
      @target_file = '/tmp/.uaa_target'
      handle = File.open(@target_file, 'w')
      handle.write("http://anywhere.com")
      handle.close
    end

    it "should set the client target when initialized" do
      @client.should_receive(:target=).with("http://anywhere.com")
      dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client, :target_file=>@target_file)
    end

    it "should save the target when command is 'target' with argument" do
      @client.stub!(:target).and_return("http://anywhere.com")
      dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client, :target_file=>@target_file)
      dispatcher.dispatch(:target, ["http://nowhere.com"], {})
      File.open(@target_file).read.should == "http://nowhere.com"
    end

    it "should show the target when command is 'target' with no argument" do
      @client.stub!(:target).and_return("http://anywhere.com")
      dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client, :target_file=>@target_file)
      dispatcher.dispatch(:target, [], {}).should == "http://anywhere.com"
    end

    it "should add protocol to target if missing" do
      @client.stub!(:target).and_return("http://anywhere.com")
      dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client, :target_file=>@target_file)
      dispatcher.dispatch(:target, ["nowhere.com"], {})
      File.open(@target_file).read.should == "http://nowhere.com"
    end

  end

  context "when operating normally" do

    before :each do
      @client.stub!(:target=)
      @dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client)
    end

    it "should use the client to login when command is 'login'" do
      @client.should_receive(:login).with({:username=>"marissa", :password=>"koala"})
      @dispatcher.dispatch(:login, [], {:username=>"marissa", :password=>"koala"})
    end

    it "should use the client to decode when command is 'decode'" do
      @client.should_receive(:decode_token).with("FOO", {})
      @dispatcher.dispatch(:decode, ["FOO"], {})
    end

    it "should use the client to get prompts when command is 'prompts'" do
      @client.should_receive(:prompts).with()
      @dispatcher.dispatch(:prompts, [], {})
    end

  end

end
