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
require 'uaa/token_coder'

describe Cloudfoundry::Uaa::TokenCoder do

  subject { Cloudfoundry::Uaa::TokenCoder.new("test_resource", "test_secret") }

  before :each do
    @tkn_body = {'foo' => "bar"}
    @tkn_secret = "test_secret"
  end

  it "should raise a decode error if the given auth header is bad" do
    expect { subject.decode(nil) }.to raise_exception(Cloudfoundry::Uaa::TokenCoder::DecodeError)
    expect { subject.decode("one two three") }.to raise_exception(Cloudfoundry::Uaa::TokenCoder::DecodeError)
  end

  it "should be able to encode/decode token" do
    tkn = subject.encode(@tkn_body)
    result = subject.decode("bEaReR #{tkn}")
    result.should_not be_nil
    result[:foo].should == "bar"
  end

  it "should raise an auth error if the token is for another resource server" do
    tkn = subject.encode({'resource_ids' => ["other_resource"], 'foo' => "bar"})
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::TokenCoder::AuthError)
  end

  it "should raise an auth error if the token is signed by an unknown signing key" do
    other = Cloudfoundry::Uaa::TokenCoder.new("test_resource", "other_secret")
    tkn = other.encode(@tkn_body)
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::TokenCoder::AuthError)
  end

  it "should raise a decode error if the token is an unknown signing algorithm" do
    segments = [Cloudfoundry::Uaa::TokenCoder.base64url_encode({"typ" => "JWT", "alg" => "BADALGO"}.to_json)]
    segments << Cloudfoundry::Uaa::TokenCoder.base64url_encode(@tkn_body.to_json)
    segments << Cloudfoundry::Uaa::TokenCoder.base64url_encode("BADSIG")
    tkn = segments.join('.')
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::TokenCoder::DecodeError)
  end

  it "should raise a decode error if the token is malformed" do
    tkn = "one.two.three.four"
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::TokenCoder::DecodeError)
    tkn = "onlyone"
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::TokenCoder::DecodeError)
  end

  it "should raise a decode error if a token segment is malformed" do
    segments = [Cloudfoundry::Uaa::TokenCoder.base64url_encode("this is not json")]
    segments << Cloudfoundry::Uaa::TokenCoder.base64url_encode("n/a")
    segments << Cloudfoundry::Uaa::TokenCoder.base64url_encode("n/a")
    tkn = segments.join('.')
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::TokenCoder::DecodeError)
  end

  it "should raise an auth error if the token has expired" do
    tkn = subject.encode({'foo' => "bar", 'expires_at' => Time.now.to_i - 60 })
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::TokenCoder::AuthError)
  end

end
