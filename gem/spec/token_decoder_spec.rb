require 'spec_helper'
require 'uaa/token_decoder'
<<<<<<< HEAD
require 'jwt'
=======
require 'uaa/jwt'
>>>>>>> update JWT token decoder to work around jwt gem bugs

describe Cloudfoundry::Uaa::TokenDecoder do

  subject { Cloudfoundry::Uaa::TokenDecoder.new("test_resource", "test_secret") }

  before :each do
    @tkn_body = {'resource_ids' => ["test_resource"], 'foo' => "bar"}
    @tkn_secret = "test_secret"
  end

<<<<<<< HEAD
  it "should be able to decode explicit token" do
    tkn = JWT.encode({'resource_ids' => ["test_resource"], 'foo' => "bar"}, "test_secret")
    result = subject.decode("bearer #{tkn}")
    result.should_not be_nil
    result[:foo].should == "bar"
  end

  #it "should be able to decode token by default", :integration=>false do
    #result = subject.decode_token(JWT.encode({foo:"bar"}, "secret"), :token_key=>"secret")
    #result.should_not be_nil
    #result[:foo].should == "bar"
  #end

  #it "should fall back to assuming an opaque token", :integration=>true do
    #@response = [200, %Q({"user_id":"#{@username}","client_id":"app"}), nil]
    #result = subject.decode_token(@token)
    #result.should_not be_nil
    #result[:user_id].should == @username
  #end
=======
  it "should raise an auth error if the given auth header is bad" do
    expect { subject.decode(nil) }.to raise_exception(Cloudfoundry::Uaa::AuthError)
    expect { subject.decode("one two three") }.to raise_exception(Cloudfoundry::Uaa::AuthError)
  end

  it "should be able to decode token" do
    tkn = JWT.encode(@tkn_body, @tkn_secret)
    result = subject.decode("bEaReR #{tkn}")
    result.should_not be_nil
    result[:foo].should == "bar"
  end

  it "should raise an auth error if the token is for another resource server" do
    tkn = JWT.encode({'resource_ids' => ["other_resource"], 'foo' => "bar"}, @tkn_secret)
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::AuthError)
  end

  it "should raise an auth error if the token is signed by an unknown signing key" do
    tkn = JWT.encode(@tkn_body, "other_secret")
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::AuthError)
  end

  it "should raise an auth error if the token is an unknown signing algorithm" do
    segments = []
    segments << JWT.base64url_encode({"typ" => "JWT", "alg" => "BADALGO"}.to_json)
    segments << JWT.base64url_encode(@tkn_body.to_json)
    segments << JWT.base64url_encode("BADSIG")
    tkn = segments.join('.')
    expect { subject.decode("bEaReR #{tkn}") }.to raise_exception(Cloudfoundry::Uaa::AuthError)
  end
>>>>>>> update JWT token decoder to work around jwt gem bugs

end
