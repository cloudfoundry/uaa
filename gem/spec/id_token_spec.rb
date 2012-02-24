require 'spec_helper'
require 'uaa/id_token'

describe Cloudfoundry::Uaa::IdToken do

  subject { Cloudfoundry::Uaa::IdToken.new("http://localhost:8080/uaa", "test_app", "test_secret", "read") }

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
