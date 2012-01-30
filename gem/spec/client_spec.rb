require 'spec_helper'

if !integration_test?
  module Cloudfoundry::Uaa::Http
    attr_writer :response
    attr_reader :input
    def perform_http_request(req)
      @input = req # keys = [:method, :url, :payload, :headers, :multipart]
      @response
    end
  end
else
  module Cloudfoundry::Uaa::Http
    attr_writer :response
  end
end

describe "Uaa client" do

  before :each do
    @client = Cloudfoundry::Uaa::Client.new
    @client.trace = true
  end

  it "should be able to get the prompts from the server", :integration=>true do
    @client.response = [200, '{"prompts":{"username":["text", "Username"], "password":["password", "Password"]}}', nil]
    @client.prompts.should_not be_empty
  end

  context "when logging in" do

    before :each do
      @client.response = [200, '{"access_token":"FOO"}', nil]
    end

    it "should be able to login, obtaining an access token, given a username and password", :integration=>true do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester")
      token.should_not be_nil
    end

    it "should concatenate scope parameters in the HTTP post", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester", :scope=>["read","write"])
      @client.input[:payload].should =~ /scope=read write/
      @default_auth = @client.input[:headers]['Authorization']
    end

    it "should use the client id if provided", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester", :client_id=>"foo")
      @client.input[:payload].should =~ /client_id=foo/
      @client.input[:headers]['Authorization'].should_not == @default_auth if @default_auth
    end

    it "should use not send the client secret in form data", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester")
      @client.input[:payload].should_not =~ /client_secret=/
    end

  end

  context "once logged in" do

    before :each do
      @client.response = [200, '{"access_token":"FOO"}', nil]
      @token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester") if @token.nil?
    end

    it "should be able to decode token info", :integration=>true do
      @client.response = [200, '{"user_id":"vcap_tester@vmware.com","client_id":"app"}', nil]
      result = @client.decode_token(@token)
      result.should_not be_nil
      result[:user_id].should == "vcap_tester@vmware.com"
    end

    it "should use the client_id if provided", :integration=>false do
      @client.response = [200, '{"user_id":"vcap_tester@vmware.com","client_id":"foo"}', nil]
      result = @client.decode_token(@token, :client_id=>"foo")
      @client.input[:headers]['Authorization'].should_not == @default_auth if @default_auth
    end

  end

end
