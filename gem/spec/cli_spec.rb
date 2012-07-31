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

# these tests CAN be run against a new UAA, but they make changes to the UAA
# admin client registration and are not repeatable for multiple test runs.
#
# Example config for integration tests with defaults:
#    ENV["UAA_CLIENT_ID"] = "admin"
#    ENV["UAA_CLIENT_SECRET"] = "adminsecret"
# if UAA_CLI_TARGET is not configured, tests will use the internal stub server
#    ENV["UAA_CLI_TARGET"] = "http://localhost:8080/uaa"

module CF::UAA

describe Cli do

  before :all do
    #Util.default_logger(:trace)
    Cli.configure("", nil, StringIO.new)
    @client_id = ENV["UAA_CLIENT_ID"] || "admin"
    @client_secret = ENV["UAA_CLIENT_SECRET"] || "adminsecret"
    if ENV["UAA_CLI_TARGET"]
      @target, @stub_uaa = ENV["UAA_CLIENT_TARGET"], nil
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

  it "should login as admin client" do
    Cli.run "target #{@target}"
    Cli.run "token client get admin -s adminsecret"
    Config.yaml.should match(/access_token/)
  end

  it "should fail to create a user account" do
    Cli.run "user add joe -p joe"
    Cli.output.string.should match /access_denied/
  end

  it "should update the admin client" do
    Cli.run "client update admin --authorities clients.write,clients.read,uaa.admin,clients.secret,scim.write,scim.read"
    Cli.output.string = ""
    Cli.run "client get admin"
    Cli.output.string.should match /scim\.read/
    Cli.output.string.should match /scim\.write/
  end

  it "should still fail to create a user account" do
    Cli.run "user add joe -p joe"
    Cli.output.string.should match /access_denied/
  end

  it "should create a user account with a new token" do
    Cli.run "token client get #{@client_id} -s #{@client_secret}"
    Cli.run "user add joe -p joe --email joe@example.com"
    Cli.output.string.should_not match /access_denied/
    Cli.output.string = ""
    Cli.run "user get joe"
    Cli.output.string.should match /joe/
  end

  it "should login with implicit grant, posted credentials" do
    Cli.run "token get joe joe"
    Cli.output.string.should match /successfully logged in/
    #pp Cli.output.string
    #pp Config.config
  end

  it "should decode the token" do
    Cli.run "token decode"
    Cli.output.string.should match /joe/
  end

  it "should get authenticated user information" do
    Cli.run "me"
    Cli.output.string.should match /joe/
  end

end

end
