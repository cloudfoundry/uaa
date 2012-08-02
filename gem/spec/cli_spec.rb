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
require 'stringio'
require 'cli'
require 'stub_uaa'
require 'pp'

# Example config to run these tests against a real UAA rather than the stub server
#    ENV["UAA_CLIENT_ID"] = "admin"
#    ENV["UAA_CLIENT_SECRET"] = "adminsecret"
#    ENV["UAA_CLI_TARGET"] = "http://localhost:8080/uaa"

module CF::UAA

describe Cli do

  before :all do
    #Util.default_logger(:trace)
    Cli.configure("", nil, StringIO.new)
    @client_id = ENV["UAA_CLIENT_ID"] || "admin"
    @client_secret = ENV["UAA_CLIENT_SECRET"] || "adminsecret"
    @test_client = "clapp_#{Time.now.to_i}"
    if ENV["UAA_CLI_TARGET"]
      @target, @stub_uaa = ENV["UAA_CLI_TARGET"], nil
    else
      @stub_uaa = StubUAA.new(@client_id, @client_secret).run_on_thread
      @target = @stub_uaa.url
    end
  end
  after :all do @stub_uaa.stop if @stub_uaa end
  before :each do Cli.output.string = "" end

  ["-v", "version", "--version"].each do |opt|
    it "should display a version with #{opt}" do
      Cli.run(opt).output.string.should match VERSION
    end
  end

  ["help", "-h"].each do |opt|
    it "should display general help with #{opt}" do
      Cli.output.string = ""
      Cli.run(opt)
      ["UAA Command Line Interface", "System Information", "Tokens", "User Accounts"].each do |s|
        Cli.output.string.should match s
      end
    end
  end

  ["help targets", "targets -h", "-h targets"].each do |opt|
    it "should display help for specific command like: #{opt}" do
      Cli.output.string = ""
      Cli.run(opt)
      Cli.output.string.should match /Display all targets/
    end
  end

  it "should set a target in the config file" do
    Cli.run("target example.com --force")
    Config.yaml.should match "https://example.com"
  end

  it "should set multiple targets and see them fully qualified in config and targets output" do
    Cli.run("target example.com --force")
    Cli.run("target example2.com --force")
    #TODO: fix stub server to fail cleanly on attempted ssl connection
    #Cli.run("target #{@stub_uaa.host}:#{@stub_uaa.port}")
    Cli.output.string = ""
    Cli.run("targets")
    Config.yaml.should match "https://example.com"
    Config.yaml.should match "https://example2.com"
    #Config.yaml.should match @stub_uaa.url
    Cli.output.string.should match "https://example.com"
    Cli.output.string.should match "https://example2.com"
    #Cli.output.string.should match @stub_uaa.url
  end

  it "should get server info" do
    Cli.run("target #{@target}")
    Cli.output.string.should match URI.parse(@target).host
    Cli.output.string = ""
    Cli.run("info")
    Cli.output.string.should match /\d.\d.\d/
    Cli.output.string.should match "prompts"
  end

  it "should check password strength" do
    Cli.run("password strength PaSsW0rd")
    Cli.output.string.should match "score"
    Cli.output.string.should match "requiredscore"
  end

  it "should login as admin client" do
    Cli.run "token client get #{@client_id} -s #{@client_secret}"
    Config.yaml.should match(/access_token/)
  end

  it "should create a test client" do
    Cli.run "client add #{@test_client} -s testsecret --authorities clients.read,scim.read " +
        "--authorized_grant_types client_credentials"
    Cli.output.string = ""
    Cli.run "client get #{@test_client}"
    Cli.output.string.should match /clients\.read/
    Cli.output.string.should match /scim\.read/
  end

  it "should login as test client" do
    Cli.run "token client get #{@test_client} -s testsecret"
    Config.yaml.should match(/access_token/)
  end

  it "should fail to create a user account as test client" do
    Cli.run "user add joe -p joe"
    Cli.output.string.should match /insufficient_scope/
  end

  it "should update the test client as the admin client" do
    Cli.run "context #{@client_id}"
    Cli.run "client update #{@test_client} --authorities scim.write,scim.read,password.write"
    Cli.output.string = ""
    Cli.run "client get #{@test_client}"
    Cli.output.string.should match /scim\.read/
    Cli.output.string.should match /scim\.write/
    Cli.output.string.should match /password\.write/
  end

  it "should still fail to create a user account as the test client" do
    Cli.run "context #{@test_client}"
    Cli.run "user add joe -p joe"
    Cli.output.string.should match "insufficient_scope"
  end

  it "should create a user account with a new token" do
    Cli.run "token client get #{@test_client} -s testsecret"
    Cli.run "user add JoE -p joe --email joe@example.com"
    Cli.output.string.should_not match /insufficient_scope/
    Cli.output.string = ""
    Cli.run "user get joe"
    Cli.output.string.should match "JoE"
  end

  it "should login with implicit grant & posted credentials as a user" do
    Cli.run "token get joe joe"
    Cli.output.string.should match "successfully logged in"
    #pp Cli.output.string
    #pp Config.config
  end

  it "should decode the token" do
    Cli.run "token decode"
    ["user_name", "exp", "aud", "scope", "client_id", "email", "user_id"].each do |a|
      Cli.output.string.should match a
    end
    #Cli.output.string.should match 'JoE'
  end

  it "should get authenticated user information" do
    Cli.run "me"
    Cli.output.string.should match 'joe'
  end

  it "should delete a client registration as admin" do
    Cli.run "context #{@client_id}"
    Cli.run "client delete #{@test_client}"
    Cli.output.string = ""
    Cli.run "clients"
    Cli.output.string.should_not match @test_client
  end

end

end
