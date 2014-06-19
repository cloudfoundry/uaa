#
# Cloud Foundry 2012.02.03 Beta
# Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache License, Version 2.0 (the "License").
# You may not use this product except in compliance with the License.
#
# This product includes a number of subcomponents with
# separate copyright notices and license terms. Your use of these
# subcomponents is subject to the terms and conditions of the
# subcomponent's license, as noted in the LICENSE file.
#

require 'rubygems'
require 'sinatra'
require './auth.rb'

get '/' do
  host = ENV['CF_APP_HOST']
  port = ENV['CF_APP_PORT']
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
