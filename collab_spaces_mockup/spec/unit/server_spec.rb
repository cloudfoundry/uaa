require 'csm/server'
require 'spec_helper'

describe 'CSM' do
	include Rack::Test::Methods	

  def app
  	CSM::CSMApp
  end

  before(:all) do
    @test_asset = spec_asset('test_asset.txt')
  end

  before(:each) do
    # make sure these get cleared so we don't have tests pass that shouldn't
    @test_each = nil
    ENV['env_test'] = nil
  end

  it 'should report its version' do
    CSM::VERSION.should =~ /\d.\d.\d/
  end

	it "should load the home page" do
		get '/'
		last_response.should be_ok
	end

	it "should get the /info in json" do
    header 'Accept', 'application/json'
    header 'Content-Type', 'application/json'
		get '/info'
		last_response.should be_ok
		output = JSON.parse(last_response.body, :symbolize_names => true)
		output[:name].should == 'vcap'
    output[:build].should == "3465a13ab528443f1afcd3c9c2861a078549b8e5"
    output[:support].should ==  "ac-support@vmware.com"
    output[:version].should ==  0.999
    output[:description].should == "VMware's Cloud Application Platform"
    #puts output
	end

end

