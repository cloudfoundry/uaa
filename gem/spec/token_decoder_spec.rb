require 'spec_helper'
require 'webmock/rspec'

describe Cloudfoundry::Uaa::TokenDecoder do
  include WebMock::API

  subject { Cloudfoundry::Uaa::TokenDecoder.new("http://localhost:8080/uaa",
      "test_resource", "test_secret") }

  before :each do
    @stub_req = stub_request(:get, "http://test_resource:test_secret@localhost:8080/uaa/check_token")
        .with(:headers => {'Accept' => 'application/json'},
            :query => {'token' => 'two', 'token_type' => 'one'})
    subject.trace = true
  end

  it "should raise an auth error if the given auth header is bad" do
    @stub_req.to_return(File.new(spec_asset('check_token_success.txt')))
    expect { subject.decode(nil).should raise_exception(AuthError) }
    expect { subject.decode("one two three").should raise_exception(AuthError) }
  end

  it "should raise a target error if the response is not json" do
    @stub_req.to_return(File.new(spec_asset('text_reply.txt')))
    expect { subject.decode("one two").should raise_exception(BadTarget) }
  end

  it "should raise a target json error if the response is 400 with valid oauth json error" do
    @stub_req.to_return(File.new(spec_asset('oauth_error_reply.txt')))
    expect { subject.decode("one two").should raise_exception(TargetJsonError) }
  end

  it "should GET decoded token hash from the check_token endpoint" do
    @stub_req.to_return(File.new(spec_asset('check_token_success.txt')))
    info = subject.decode("one two")
    info.should include(:resource_id => "test_resource")
    info.should include(:email => "derek@gmail.com")
  end

end
