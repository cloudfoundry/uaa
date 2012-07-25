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
require 'cli/base'

module CF::UAA

describe TokenCoder do

  subject { TokenCoder.new("test_resource", "test_secret", OpenSSL::PKey::RSA.generate(512) ) }

  before :each do
    @tkn_body = {'foo' => "bar"}
    @tkn_secret = "test_secret"
  end

  it "should raise a decode error if the given auth header is bad" do
    expect { subject.decode(nil) }.to raise_exception(DecodeError)
    expect { subject.decode("one two three") }.to raise_exception(DecodeError)
  end

  it "should be able to encode/decode a token using a symmetrical key" do
    tkn = subject.encode(@tkn_body, 'HS512')
    result = subject.decode("bEaReR #{tkn}")
    result.should_not be_nil
    result[:foo].should == "bar"
  end

  it "should be able to encode/decode a token using pub/priv key" do
    tkn = subject.encode(@tkn_body, 'RS256')
    result = subject.decode("bEaReR #{tkn}")
    result.should_not be_nil
    result[:foo].should == "bar"
  end

  it "should be able to encode/decode a token using pub/priv key from PEM" do
    pem = <<-DATA.gsub(/^ +/, '')
      -----BEGIN RSA PRIVATE KEY-----
      MIIBOwIBAAJBAN+5O6n85LSs/fj46Ht1jNbc5e+3QX+suxVPJqICvuV6sIukJXXE
      zfblneN2GeEVqgeNvglAU9tnm3OIKzlwM5UCAwEAAQJAEhJ2fV7OYsHuqiQBM6fl
      Pp4NfPXCtruPSUNhjYjHPuYpnqo6cpuUNAzRvqAdDkJJsPCPt1E5AWOYUYOmLE+d
      AQIhAO/XxMb9GrTDyqJDvS8T1EcJpLCaUIReae0jSg1RnBrhAiEA7st6WLmOyTxX
      JgLcO6LUfW6RsE3pgi9NGL25P3eOAzUCIQDUFKi1CJR36XWh/GIqYc9grX9KhnnS
      QqZKAd12X4a5IQIhAMTOJKaNP/Xwai7kupfX6mL6Rs5UWDg4PcU/UDbTlNJlAiBv
      2yrlT5h164jGCxqe7++1kIl4ollFCgz6QJ8lcmb/2Q==
      -----END RSA PRIVATE KEY-----
    DATA
    coder = TokenCoder.new("test_resource", nil, pem)
    tkn = coder.encode(@tkn_body, 'RS256')
    result = coder.decode("bEaReR #{tkn}")
    result.should_not be_nil
    result[:foo].should == "bar"
  end

  it "should be able to encode/decode with no signature" do
    tkn = subject.encode(@tkn_body, 'none')
    result = subject.decode("bEaReR #{tkn}")
    result.should_not be_nil
    result[:foo].should == "bar"
  end

  it "should raise an error if the signing algorithm is not supported" do
    expect { subject.encode(@tkn_body, 'baz') }.to raise_exception(ArgumentError)
  end

  it "should raise an auth error if the token is for another resource server" do
    tkn = subject.encode({'aud' => ["other_resource"], 'foo' => "bar"})
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(AuthError)
  end

  it "should raise a decode error if the token is signed by an unknown signing key" do
    other = TokenCoder.new("test_resource", "other_secret", nil)
    tkn = other.encode(@tkn_body)
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(DecodeError)
  end

  it "should raise a decode error if the token is an unknown signing algorithm" do
    segments = [TokenCoder.base64url_encode({"typ" => "JWT", "alg" => "BADALGO"}.to_json)]
    segments << TokenCoder.base64url_encode(@tkn_body.to_json)
    segments << TokenCoder.base64url_encode("BADSIG")
    tkn = segments.join('.')
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(DecodeError)
  end

  it "should raise a decode error if the token is malformed" do
    tkn = "one.two.three.four"
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(DecodeError)
    tkn = "onlyone"
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(DecodeError)
  end

  it "should raise a decode error if a token segment is malformed" do
    segments = [TokenCoder.base64url_encode("this is not json")]
    segments << TokenCoder.base64url_encode("n/a")
    segments << TokenCoder.base64url_encode("n/a")
    tkn = segments.join('.')
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(DecodeError)
  end

  it "should raise an auth error if the token has expired" do
    tkn = subject.encode({'foo' => "bar", 'exp' => Time.now.to_i - 60 })
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(AuthError)
  end

  it "should decode a token, but not require validatation" do
    token = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6ImY1MTgwMjExLWVkYjItNGQ4OS1hNmQwLThmNGVjMTE0NTE4YSIsInJlc291cmNlX2lkcyI6WyJjbG91ZF9jb250cm9sbGVyIiwicGFzc3dvcmQiXSwiZXhwaXJlc19hdCI6MTMzNjU1MTc2Niwic2NvcGUiOlsicmVhZCJdLCJlbWFpbCI6Im9sZHNAdm13YXJlLmNvbSIsImNsaWVudF9hdXRob3JpdGllcyI6WyJST0xFX1VOVFJVU1RFRCJdLCJleHBpcmVzX2luIjo0MzIwMCwidXNlcl9hdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwidXNlcl9pZCI6Im9sZHNAdm13YXJlLmNvbSIsImNsaWVudF9pZCI6InZtYyIsInRva2VuX2lkIjoiZWRlYmYzMTctNWU2Yi00YmYwLWFmM2ItMTA0OWRjNmFlYjc1In0.XoirrePfEujnZ9Vm7SRRnj3vZEfRp2tkjkS_OCVz5Bs"
    info = TokenCoder.decode(token, nil, nil, false)
    info[:id].should_not be_nil
    info[:email].should == "olds@vmware.com"
    #puts Time.at(info[:exp].to_i)
    #BaseCli.pp info
  end


end

end
