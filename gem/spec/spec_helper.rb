if ENV['COVERAGE']
  require "simplecov"
  SimpleCov.start
end

require 'rspec'

def integration_test?
  ENV['INTEGRATION_TEST']
end

RSpec.configure do |config|
  #only run examples with 'integration' specified in metadata
  config.filter_run(:integration => true) if integration_test?
end

def spec_asset(filename)
  File.expand_path(File.join(File.dirname(__FILE__), "assets", filename))
end
