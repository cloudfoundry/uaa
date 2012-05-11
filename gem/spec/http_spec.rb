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
require 'cli/stub_server'

module CF::UAA

describe Http do

  include Http

  before :each do
    @debug = false
    @target = StubServer.url
    StubServer.responder { <<-REPLY.gsub(/^ +/, '') }
      HTTP/1.1 200 OK
      Connection: close
      Server: http/specs
      Date: Thu, 03 Mar 2011 19:38:32 GMT
      Content-Type: text/plain
      Content-Length: 3

      Foo
    REPLY
    #StubServer.responder do |request, reply|
      #reply.headers[:content_type] = "text/plain"
      #reply.body = "Foo"
      #reply
    #end
  end

  it "should get something from stub server on a fiber" do
    StubServer.fiber_request do
      f = Fiber.current
      http = EM::HttpRequest.new(@target).get
      http.errback { f.resume "error" }
      http.callback {
        http.response_header.http_status.should == 200
        f.resume http.response
      }
      res = Fiber.yield
      res.should == "Foo"
    end
  end

  it "should be able to use persistent connections from stubserver" do
    StubServer.responder do |request, reply|
      reply.headers[:content_type] = "text/plain"
      reply.body = "Foo"
      reply
    end
    StubServer.fiber_request do
      f = Fiber.current
      conn = EM::HttpRequest.new(@target)
      req1 = conn.get keepalive: true
      req1.errback { f.resume "error1" }
      req1.callback {
        req2 = conn.get
        req2.errback { f.resume req2.error }
        req2.callback { f.resume req2.response }
       }
      res = Fiber.yield
      res.should == "Foo"
    end
  end

  it "should get something from stub server on a thread" do
    StubServer.thread_request do
      resp = RestClient.get target
      resp.code.should == 200
      resp.body.should match(/Foo/)
    end
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
      StubServer.request do
        @target = "http://bad~host~name/"
        expect { http_get("/") }.to raise_exception(BadTarget)
      end
    end

    it "fail cleanly for a get operation, no connection to address" do
      StubServer.request do
        @target = "http://127.0.0.1:30000"
        expect { http_get("/") }.to raise_exception(BadTarget)
      end
    end

    it "fail cleanly for a get operation with bad response" do
      StubServer.responder { "badly formatted http response" }
      StubServer.request do
        expect { http_get("/") }.to raise_exception(HTTPException)
      end
    end

    it "work for a get operation to a valid address" do
      StubServer.request do
        status, body, headers = http_get("/")
        status.should == 200
        body.should == "Foo"
      end
    end

    it "should send debug information to a custom logger" do
      class CustomLogger
        attr_reader :log
        def initialize
          @log = ""
        end
        def debug(str)
          @log << str
        end
      end
      @debug = true
      @logger = clog = CustomLogger.new
      clog.log.should be_empty
      StubServer.request { http_get("/") }
      clog.log.should_not be_empty
    end

  end

  context "on a fiber" do
    before(:all) { StubServer.use_fiber = @async = true }
    it_should_behave_like "http client"
  end

  context "on a thread" do
    before(:all) { StubServer.use_fiber = @async = false }
    it_should_behave_like "http client"
  end

end

end
