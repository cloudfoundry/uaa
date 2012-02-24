require 'spec_helper'
require 'uaa/token_coder'

describe Cloudfoundry::Uaa::TokenCoder do

  subject { Cloudfoundry::Uaa::TokenCoder.new("test_resource", "test_secret") }

  before :each do
    @tkn_body = {'foo' => "bar"}
    @tkn_secret = "test_secret"
  end

  it "should raise an auth error if the given auth header is bad" do
    expect { subject.decode(nil) }.to raise_exception(Cloudfoundry::Uaa::AuthError)
    expect { subject.decode("one two three") }.to raise_exception(Cloudfoundry::Uaa::AuthError)
  end

  it "should be able to encode/decode token" do
    tkn = subject.encode(@tkn_body)
    result = subject.decode("bEaReR #{tkn}")
    result.should_not be_nil
    result[:foo].should == "bar"
  end

  it "should raise an auth error if the token is for another resource server" do
    tkn = subject.encode({'resource_ids' => ["other_resource"], 'foo' => "bar"})
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::AuthError)
  end

  it "should raise an auth error if the token is signed by an unknown signing key" do
    other = Cloudfoundry::Uaa::TokenCoder.new("test_resource", "other_secret")
    tkn = other.encode(@tkn_body)
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::AuthError)
  end

  it "should raise an auth error if the token is an unknown signing algorithm" do
    segments = [Cloudfoundry::Uaa::TokenCoder.base64url_encode({"typ" => "JWT", "alg" => "BADALGO"}.to_json)]
    segments << Cloudfoundry::Uaa::TokenCoder.base64url_encode(@tkn_body.to_json)
    segments << Cloudfoundry::Uaa::TokenCoder.base64url_encode("BADSIG")
    tkn = segments.join('.')
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::AuthError)
  end

end
