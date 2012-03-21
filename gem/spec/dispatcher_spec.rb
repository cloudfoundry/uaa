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
require 'cli'
require 'uaa/client'

describe "Uaa cli dispatcher" do

  before :each do
    @client = mock(Cloudfoundry::Uaa::Client)
    @client.stub!(:target=)
    @client.stub!(:token=)
    @client.stub!(:target).and_return("http://anywhere.com")
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
      dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client, :target_file=>@target_file)
      dispatcher.dispatch(:target, ["http://nowhere.com"], {})
      File.open(@target_file).read.should == "http://nowhere.com"
    end

    it "should show the target when command is 'target' with no argument" do
      dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client, :target_file=>@target_file)
      dispatcher.dispatch(:target, [], {}).should == "http://anywhere.com"
    end

    it "should add protocol to target if missing" do
      dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client, :target_file=>@target_file)
      dispatcher.dispatch(:target, ["nowhere.com"], {})
      File.open(@target_file).read.should == "http://nowhere.com"
    end

  end

  context "when token file is customized" do

    before :each do
      Dir.mkdir "/tmp" unless Dir.exist? "/tmp"
      @token_file = '/tmp/.uaa_token'
      handle = File.open(@token_file, 'w')
      handle.write('{"http://anywhere.com":"FOO"}')
      handle.close
    end

    it "should set the client token when initialized" do
      @client.should_receive(:token=).with("FOO")
      dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client, :token_file=>@token_file)
    end


    it "should save the token when command is 'token' with argument" do
      @client.should_receive(:token=).with("FOO")
      @client.stub(:token).and_return("FOO")
      dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client, :token_file=>@token_file)
      @client.should_receive(:login).with({:username=>"marissa", :password=>"koala"}).and_return("BAR")
      @client.should_receive(:token=).with("BAR")
      dispatcher.dispatch(:login, [], {:username=>"marissa", :password=>"koala", :save_token=>true})
      File.open(@token_file).read.should == '{"http://anywhere.com":"BAR"}'
    end

    it "should not save the token when :save_token is false" do
      @client.should_receive(:token=).with("FOO")
      @client.stub(:token).and_return("FOO")
      dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client, :token_file=>@token_file)
      @client.should_receive(:login).with({:username=>"marissa", :password=>"koala"}).and_return("BAR")
      dispatcher.dispatch(:login, [], {:username=>"marissa", :password=>"koala", :save_token=>false})
      File.open(@token_file).read.should == '{"http://anywhere.com":"FOO"}'
    end

  end

  context "when operating normally" do

    before :each do
      @client.stub!(:target=)
      @client.stub!(:target).and_return("http://uaa.vcap.me")
      @dispatcher = Cloudfoundry::Uaa::Dispatcher.new(:client=>@client)
      @dispatcher.stub(:save_token)
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
