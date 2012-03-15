#
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
#

require 'spec_helper'
require 'uaa/http'
require 'stub_server'

describe Cloudfoundry::Uaa::Http do

  include Cloudfoundry::Uaa::Http

  before :all do
    @trace = true
    @async = true
  end

  it "should raise an auth error if the uri is nil or invalid" do
    req = { :method => :get, :url => nil, :payload => nil, :headers => nil }
    expect { perform_ahttp_request(req) }.to raise_exception(Addressable::URI::InvalidURIError)
  end

  it "should get something from stub server" do
    EM.run {
      @s = StubServer.new("HTTP/1.0 200 OK\nConnection: close\n\nFoo")
      http = EventMachine::HttpRequest.new('http://127.0.0.1:8081/').get
      http.errback {
        "we should not get a call to the errback block".should be_nil
        @s.stop
        EventMachine.stop
      }
      http.callback {
        http.response.should match(/Foo/)
        http.response_header['CONTENT_LENGTH'].should be_nil
        @s.stop
        EventMachine.stop
      }
    }
  end

  it "should get something from stub server on a fiber" do
    EM.run do
      @s = StubServer.new("HTTP/1.0 200 OK\nConnection: close\n\nFoo")
      Fiber.new {
        f = Fiber.current
        http = EventMachine::HttpRequest.new('http://127.0.0.1:8081/').get
        http.errback { f.resume "error" }
        http.callback { http.response.should match(/Foo/); f.resume "good" }
        Fiber.yield.should == "good"
      }.resume
      EM::Timer.new(1) { @s.stop; EventMachine.stop }
    end
    # TODO: got to be something better than a timer. Check for leftover fibers
  end

  it "should fail cleanly for a failed dns lookup" do
    EM.run do
      Fiber.new {
        @target = "http://bad.example.bad"
        expect { http_get("/") }.to raise_exception(HTTPException)
      }.resume
      EM::Timer.new(1) { EventMachine.stop }
    end
    # TODO: got to be something better than a timer. Check for leftover fibers
  end

  it "should fail cleanly for a get operation, no connection to address" do
    EM.run do
      Fiber.new {
        @target = "http://127.0.0.1:30000"
        expect { http_get("/") }.to raise_exception(HTTPException)
      }.resume
      EM::Timer.new(1) { EventMachine.stop }
    end
    # TODO: got to be something better than a timer. Check for leftover fibers
  end

  it "should work for a get operation to a valid address" do
    EM.run do
      @s = StubServer.new("HTTP/1.0 200 OK\nConnection: close\n\nFoo")
      Fiber.new {
        @target = "http://127.0.0.1:8081"
        status, body, headers = http_get("/")
        status.should == 200
        body.should == "Foo"
      }.resume
      EM::Timer.new(1) { @s.stop; EventMachine.stop }
    end
    # TODO: got to be something better than a timer. Check for leftover fibers
  end

end
