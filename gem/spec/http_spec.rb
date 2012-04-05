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
require 'stub_server'

describe CF::UAA::Http do

  include CF::UAA::Http

  before :each do
    @trace = true
    @target = StubServer.url
    StubServer.responder { <<-REPLY.gsub(/^ +/, '') }
      HTTP/1.0 200 OK
      Connection: close
      Server: nginx/0.7.65
      Date: Thu, 03 Mar 2011 19:38:32 GMT
      Content-Type: text/plain
      Content-Length: 3

      Foo
    REPLY
  end

  it "should get something from stub server on a fiber" do
    StubServer.fiber_request do
      f = Fiber.current
      http = EM::HttpRequest.new(@target).get
      http.errback { f.resume "error"}
      http.callback {
        http.response_header.http_status.should == 200
        http.response.should match(/Foo/)
        f.resume "good"
      }
      res = Fiber.yield
      res.should == "good"
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

    it "fail cleanly for a failed dns lookup" do
      StubServer.request do
        @target = "http://bad.example.bad"
        expect { http_get("/") }.to raise_exception(CF::UAA::BadTarget)
      end
    end

    it "fail cleanly for a get operation, no connection to address" do
      StubServer.request do
        @target = "http://127.0.0.1:30000"
        expect { http_get("/") }.to raise_exception(CF::UAA::BadTarget)
      end
    end

    it "fail cleanly for a get operation with bad response" do
      StubServer.responder { "badly formatted http response" }
      StubServer.request do
        expect { http_get("/") }.to raise_exception(CF::UAA::HTTPException)
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
      @trace = true
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
