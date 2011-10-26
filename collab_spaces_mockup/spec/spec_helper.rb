#$:.unshift('./lib')
require 'spec'
require 'rack/test'

def spec_asset(filename)
  File.expand_path(File.join(File.dirname(__FILE__), "assets", filename))
end
