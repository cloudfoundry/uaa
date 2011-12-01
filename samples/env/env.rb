require 'rubygems'
require 'sinatra'
require './auth.rb'

get '/' do
  host = ENV['VMC_APP_HOST']
  port = ENV['VMC_APP_PORT']
  %({"message" : "XXXXX Hello from Ruby!", "host": "#{host}", "port": "#{port}"}\n)
end

get '/env' do
  res = %({\n  "env" : {\n)
  ENV.each_with_index do |(k, v), i|
    i > 0 && res << ",\n"
    res << %(   "#{k}": "#{v}")
  end
  res << %(},\n  "request" : {\n)
  request.env.each_with_index do |(k, v), i|
    i > 0 && res << ",\n"
    res << %(   "#{k}": "#{v}")
  end
  res << "  }\n}\n"
  res
end
