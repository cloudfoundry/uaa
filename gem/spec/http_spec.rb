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
require 'webmock/rspec'
require 'eventmachine'
require 'fiber'

describe Cloudfoundry::Uaa::Http do
  include WebMock::API

  include Cloudfoundry::Uaa::Http

  context "uri validation" do
    it "should raise an auth error if the uri is nil or invalid" do
      req = {
        :method => :get, :url => nil,
        :payload => nil, :headers => nil
      }
      expect { perform_ahttp_request(req) }.to raise_exception(Addressable::URI::InvalidURIError)
    end
  end

  context "it should be able to perform a valid http operation" do
    before :each do
      @auth_headers = {"Authorization" => "dGVzdDpwYXNzd29yZA=="}
      @stub_req = stub_request(:any, "http://localhost:8080")
                  .with(:headers => @auth_headers)
                  .to_return(:status => 200, 
                          :body => "{\"result\" => \"Success\"}", 
                          :headers => {"Content-Type" => "application/json"})

    end

    shared_examples_for "any operation" do
      it "should work for a get operation" do 
        EM.run_block {
          Fiber.new {
            req = {
              :method => @method, :url => "http://localhost:8080",
              :payload => nil, :headers => @auth_headers
            }
            code, body, headers = perform_ahttp_request(req)
            code.should eql(200)
            body.should eql("{\"result\" => \"Success\"}")
            headers.should eql("CONTENT_TYPE" => "application/json", "CONTENT_LENGTH" => "23")
          }.resume
        }
      end
    end

    context "using the get method" do
      before :all do
        @method = :get
      end
      it_should_behave_like "any operation"
    end

    context "using the get method" do
      before :all do
        @method = :put
      end
      it_should_behave_like "any operation"
    end
    
    context "using the get method" do
      before :all do
        @method = :post
      end
      it_should_behave_like "any operation"
    end
    
    context "using the get method" do
      before :all do
        @method = :delete
      end
      it_should_behave_like "any operation"
    end

  end
end
