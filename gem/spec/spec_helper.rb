require 'cli'
require 'uaa'
require 'rspec'
require 'simplecov'

def integration_test?
  ENV['INTEGRATION_TEST']
end
  
def coverage?
  ENV['COVERAGE']
end
  
RSpec.configure do |config|
  #only run examples with 'integration' specified in metadata
  config.filter_run(:integration => true) if integration_test?
end

SimpleCov.start if coverage?

