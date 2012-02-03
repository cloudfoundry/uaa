require 'spec_helper'

if !integration_test?
  module Cloudfoundry::Uaa::Http
    attr_writer :response
    attr_reader :input
    def perform_http_request(req)
      @input = req # keys = [:method, :url, :payload, :headers, :multipart]
      @response
    end
    def json_get(url)
      if url == "/login" then
        return {:prompts=>{:username=>["text", "Username"], :password=>["password", "Password"]}}
      end
      @response[1] if @response
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

  context "when logging in with password grant" do

    before :each do
      @client.response = [200, '{"access_token":"FOO"}', nil]
    end

    it "should post to the token endpoint", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester", :client_id=>"foo", :grant_type=>"password")
      @client.input[:url].should =~ /\/token/
      @client.input[:method].should == :post
    end

    it "should include the grant type", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester", :client_id=>"foo", :grant_type=>"password")
      @client.input[:payload].should =~ /grant_type=password/
    end

    it "should not have a redirect uri", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester", :grant_type=>"password")
      @client.input[:payload].should_not =~ /redirect_uri=/
    end

    it "should be able to login, obtaining an access token, given a username and password", :integration=>true do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester", :grant_type=>"password", :client_id=>"app", :client_secret=>"appclientsecret")
      token.should_not be_nil
    end

    it "should use the client id if provided", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester", :client_id=>"foo", :grant_type=>"password")
      @client.input[:payload].should =~ /client_id=foo/
      @client.input[:headers]['Authorization'].should_not == @default_auth if @default_auth
    end

    it "should use not send the client secret in form data", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester", :grant_type=>"password")
      @client.input[:payload].should_not =~ /client_secret=/
    end

    it "should concatenate scope parameters in the HTTP post", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester", :scope=>["read","write"], :grant_type=>"password")
      @client.input[:payload].should =~ /scope=read write/
      @default_auth = @client.input[:headers]['Authorization']
    end

    it "should add basic auth", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester", :grant_type=>"password")
      @client.input[:headers]['Authorization'].should =~ /Basic .*/
    end

  end

  context "when logging in with implicit grant" do

    before :each do
      @client.response = [302, nil, {'Location'=>'urn:oauth:implicit#expires_in=100&access_token=FOO&scope=read'}]
    end

    it "should post to the authorize endpoint", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester")
      @client.input[:url].should =~ /\/authorize/
      @client.input[:method].should == :post
    end

    it "should convert credentials to json", :integration=>false do
      token = @client.login(:username=>"vcap_tester@vmware.com", :password=>"tester")
      @client.input[:payload].should =~ /credentials={"/
    end

    it "should have a redirect uri", :integration=>false do
      token = @client.login(:credentials=>{:username=>"vcap_tester@vmware.com", :password=>"tester"})
      @client.input[:payload].should =~ /redirect_uri=/
    end

    it "should jsonise a hash in the form data", :integration=>false do
      token = @client.login(:credentials=>{:username=>"vcap_tester@vmware.com", :password=>"tester"})
      @client.input[:payload].should =~ /credentials={"username":"vcap_tester@vmware.com"/
    end

    it "should be able to login, obtaining an access token, given credentials", :integration=>true do
      token = @client.login(:credentials=>{:username=>"vcap_tester@vmware.com", :password=>"tester"})
      token.should_not be_nil
    end

  end

  context "once logged in with password grant" do

    before :each do
      @client.response = [200, '{"access_token":"FOO"}', nil]
      @client.client_id = "app"
      @client.client_secret = "appclientsecret"
      @client.grant_type = "password"
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
