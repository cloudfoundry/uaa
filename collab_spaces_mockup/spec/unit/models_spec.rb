require 'spec_helper'
require 'csm/models'
require 'csm/version'

describe 'CSM' do

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

# tests here for create orgs, validate unique fields, e.g. email address unique per user but can be used on other accounts. 

end
