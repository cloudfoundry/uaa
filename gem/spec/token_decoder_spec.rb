require 'spec_helper'

describe Cloudfoundry::Uaa::TokenDecoder do

  subject { Cloudfoundry::Uaa::TokenDecoder.new("http://localhost:8080/uaa", "test_resource", "test_secret") }

  before :each do
    if !integration_test?
      subject.stub!(:perform_http_request) do |req|
        @input = req
        @response
      end
    end
    subject.trace = true
  end

  it "should do something", :integration=>false do
      subject.trace.should_not be_nil
    end

end
