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

describe Cloudfoundry::Uaa::Http do

  include Cloudfoundry::Uaa::Http

  before :all do
    #@trace = true
    @target = StubServer.url
    #StubServer.responder { |indata| puts indata; <<-REPLY.gsub(/^ +/, '') }
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

  it "should get something from stub server on a thread" do
    StubServer.thread_request do
      resp = RestClient.get target
      resp.code.should == 200
      resp.body.should match(/Foo/)
    end
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

  shared_examples_for "thread/fiber" do

    it "should fail cleanly for a failed dns lookup" do
      StubServer.request(@async) do
        @target = "http://bad.example.bad"
        expect { http_get("/") }.to raise_exception(BadTarget)
      end
    end

    it "should fail cleanly for a get operation, no connection to address" do
      StubServer.request(@async) do
        @target = "http://127.0.0.1:30000"
        expect { http_get("/") }.to raise_exception(BadTarget)
      end
    end

    it "should work for a get operation to a valid address" do
      StubServer.request(@async) do
        status, body, headers = http_get("/")
        status.should == 200
        body.should == "Foo"
      end
    end

  end

  context "on a fiber" do
    before(:all) { @async = true }
    it_should_behave_like "thread/fiber"
  end

  context "on a thread" do
    before(:all) { @async = false }
    it_should_behave_like "thread/fiber"
  end

end
