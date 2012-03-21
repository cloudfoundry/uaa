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

  def run_test_on_fiber
    EM.run do
      @stubs = StubServer.new("HTTP/1.0 200 OK\nConnection: close\n\nFoo", 8083)
      EM::Timer.new(2) { @stubs.stop; EM.stop; fail "timed out" }
      Fiber.new { yield; @stubs.stop; EM.stop }.resume
    end
  end

  before :all do
    @trace = true
    @async = true
  end

  it "should raise an auth error if the uri is nil or invalid" do
    req = { :method => :get, :url => nil, :payload => nil, :headers => nil }
    expect { perform_ahttp_request(req) }.to raise_exception(Addressable::URI::InvalidURIError)
  end

  it "should get something from stub server on a fiber" do
    run_test_on_fiber do
      f = Fiber.current
      http = EM::HttpRequest.new('http://127.0.0.1:8083/').get
      http.errback { f.resume "error"}
      http.callback {
        http.response.should match(/Foo/)
        http.response_header['CONTENT_LENGTH'].should be_nil
        f.resume "good"
      }
      res = Fiber.yield
      res.should == "good"
    end
  end

  it "should fail cleanly for a failed dns lookup" do
    run_test_on_fiber do
      @target = "http://bad.example.bad"
      expect { http_get("/") }.to raise_exception(HTTPException)
    end
  end

  it "should fail cleanly for a get operation, no connection to address" do
    run_test_on_fiber do
      @target = "http://127.0.0.253:30000"
      expect { http_get("/") }.to raise_exception(HTTPException)
    end
  end

  it "should work for a get operation to a valid address" do
    run_test_on_fiber do
      @target = "http://127.0.0.1:8083"
      status, body, headers = http_get("/")
      status.should == 200
      body.should == "Foo"
    end
  end

end
