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

module CF::UAA

describe Cli do

  before :all do
    #Util.default_logger(:trace)
    @stub_uaa = StubUAA.new.run_on_thread
    cadmin_group = @stub_uaa.scim.add(:group, {display_name: "client_admin"})
    uadmin_group = @stub_uaa.scim.add(:group, {display_name: "user_admin"})
    openid_group = @stub_uaa.scim.add(:group, {display_name: "openid"})
    @openid = openid_group[:id]
    @stub_uaa.scim.add(:client, {display_name: "admin", password: "adminsecret",
        authorized_grant_types: ["client_credentials"],
        groups: [cadmin_group[:id]], access_token_validity: 5 * 60 })
    @stub_uaa.scim.add(:client, {display_name: "vmc",
        authorized_grant_types: ["implicit"],
        requestable_scopes: [@openid], access_token_validity: 5 * 60 })
    Cli.configure("", nil, StringIO.new)
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
    Cli.run("target #{@stub_uaa.url}")
    Cli.output.string.should match @stub_uaa.host
    Cli.output.string = ""
    Cli.run("uaa")
    Cli.output.string.should match VERSION
    Cli.output.string.should match "prompts"
  end

  it "should login as admin client" do
    Cli.run "target #{@stub_uaa.url}"
    Cli.run "token client get admin -s adminsecret"
    Config.yaml.should match(/access_token/)
  end

  it "should fail to create a user account" do
    Cli.run "user add joe -p joe"
    Cli.output.string.should match /access denied/
  end

  it "should update the admin client" do
    Cli.run "client update admin --authorities client_admin,user_admin"
    Cli.output.string = ""
    Cli.run "client get admin"
    Cli.output.string.should match /client_admin/
    Cli.output.string.should match /user_admin/
  end

  it "should still fail to create a user account" do
    Cli.run "user add joe -p joe"
    Cli.output.string.should match /access denied/
  end

  it "should create a user account with a new token" do
    Cli.run "token client get admin -s adminsecret"
    Cli.run "user add joe -p joe --groups #{@openid} --email joe@example.com"
    Cli.output.string.should_not match /access denied/
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
    Cli.run "who am i"
    Cli.output.string.should match /joe/
  end

end

end
