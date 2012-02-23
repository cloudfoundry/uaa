require 'spec_helper'
require 'uaa/token_decoder'
require 'jwt'

describe Cloudfoundry::Uaa::TokenDecoder do

  subject { Cloudfoundry::Uaa::TokenDecoder.new("test_resource", "test_secret") }

  before :each do
    subject.trace = true
  end

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

end
