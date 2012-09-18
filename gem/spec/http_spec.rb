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
require 'uaa/http'
require 'uaa/version'
require 'cli/stub_server'

module CF::UAA

class StubHttp < Stub::Base
  route(:get, '/') { reply_in_kind "welcome to stub http, version #{VERSION}" }
  route( :get, '/bad') { reply.headers[:location] = ":;+)(\/"; reply_in_kind(3, "bad http status code") }
end

describe Http do

  include Http
  include SpecHelper

  before :all do
    @stub_http = Stub::Server.new(StubHttp, Util.default_logger(:info)).run_on_thread
  end

  after :all do @stub_http.stop if @stub_http end

  it "should get something from stub server on a fiber" do
    @async = true
    frequest {
      f = Fiber.current
      http = EM::HttpRequest.new("#{@stub_http.url}/").get
      http.errback { f.resume "error" }
      http.callback {
        http.response_header.http_status.should == 200
        f.resume http.response
      }
      Fiber.yield
    }.should match /welcome to stub http/
  end

  it "should be able to use persistent connections from stubserver" do
    @async = true
    frequest {
      f = Fiber.current
      conn = EM::HttpRequest.new("#{@stub_http.url}/")
      req1 = conn.get keepalive: true
      req1.errback { f.resume "error1" }
      req1.callback {
        req2 = conn.get
        req2.errback { f.resume req2.error }
        req2.callback { f.resume req2.response }
      }
      Fiber.yield
    }.should match /welcome to stub http/
  end

  it "should get something from stub server on a thread" do
    @async = false
    resp = RestClient.get("#{@stub_http.url}/")
    resp.code.should == 200
    resp.body.should match /welcome to stub http/
  end

  shared_examples_for "http client" do

    # the following is intended to test that a failed dns lookup will fail the
    # same way on the buggy em-http-request 1.0.0.beta3 client as it does on
    # the rest-client. However, some networks (such as the one I am on now)
    # configure the dhcp client with a dns server that will resolve
    # every name as a valid address, e.g. bad.example.bad returns an address
    # to a service signup screen. I have tried stubbing the code in various
    # ways:
     # EventMachine.stub(:connect) { raise EventMachine::ConnectionError, "fake error for bad dns lookup" }
     # EventMachine.unstub(:connect)
     # Socket.stub(:gethostbyname) { raise SocketError, "getaddrinfo: Name or service not known" }
     # Socket.unstub(:gethostbyname)
    # This has had varied success but seems rather brittle. Currently I have opted
    # to just make the domain name invalid with tildes, but this may not test
    # the desired code paths
    it "fail cleanly for a failed dns lookup" do
      result = frequest { http_get("http://bad~host~name/") }
      result.should be_an_instance_of BadTarget
    end

    it "fail cleanly for a get operation, no connection to address" do
      result = frequest { http_get("http://127.0.0.1:30000/") }
      result.should be_an_instance_of BadTarget
    end

    it "fail cleanly for a get operation with bad response" do
      frequest { http_get(@stub_http.url, "/bad") }.should be_an_instance_of HTTPException
    end

    it "work for a get operation to a valid address" do
      status, body, headers = frequest { http_get(@stub_http.url, "/") }
      status.should == 200
      body.should match /welcome to stub http/
    end

    it "should send debug information to a custom logger" do
      class CustomLogger
        attr_reader :log
        def initialize; @log = "" end
        def debug(str = nil) ; @log << (str ? str : yield) end
      end
      @logger = clog = CustomLogger.new
      clog.log.should be_empty
      frequest { http_get(@stub_http.url, "/") }
      clog.log.should_not be_empty
    end
  end

  context "on a fiber" do
    before(:all) { @async = true }
    it_should_behave_like "http client"
  end

  context "on a thread" do
    before(:all) { @async = false }
    it_should_behave_like "http client"
  end

end

end
