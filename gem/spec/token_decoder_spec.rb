require 'spec_helper'

describe Cloudfoundry::Uaa::TokenDecoder do

  before :each do
    subject.stub!(:perform_http_request) do
      @response # [status, body, headers]
    end
    # subject.trace = true
  end

  subject { Cloudfoundry::Uaa::TokenDecoder.new("http://localhost:8080/uaa",
      "test_resource", "test_secret") }

  before :each do
    subject.trace = true
  end

  it "should raise an auth error if the given auth header is bad" do
    @response = [401, nil, nil]
    expect { subject.decode(nil).should raise_exception(AuthError) }
    expect { subject.decode("one two three").should raise_exception(AuthError) }
  end

  it "should raise a target error if the response is not json" do
    @response = [200, "foo bar", nil]
    expect { subject.decode("one two").should raise_exception(BadTarget) }
  end

  it "should raise a target json error if the response is 400 with valid oauth json error" do
    @response = [400, '{"error":"bad_request","description":"Bad request"}', nil]
    expect { subject.decode("one two").should raise_exception(TargetJsonError) }
  end

  it "should GET decoded token hash from the check_token endpoint" do
    @response = [200, '{"resource_ids": ["one_resource", "test_resource", "other_resource"],"email":"derek@gmail.com"}', nil]
    info = subject.decode("one two")
    info.should include(:resource_ids)
    info[:resource_ids].should include("test_resource")
    info.should include(:email => "derek@gmail.com")
  end

end
