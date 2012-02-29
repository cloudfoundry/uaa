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

require "sinatra/base"

module Sinatra

  module Protection

    enable :sessions

    get('/login') do
      puts "User wants to login"
      %({"message" : "please POST back to this location with parameters specified", "parameters" : ["username", "password"]}\n)
    end
    
    post('/login') do
      if params[:username] == 'marissa' && params[:password] == 'koala'
        puts "Found #{params[:username]} with request: #{session['request']}"
        session['user_name'] = params[:username]
        location = '/'
        if session['request']
          location = session['request']
          session['request'] = nil
        end
        puts "Normal redirect to #{location}"
        redirect location
      else
        puts "Invalid login request, redirecting to login page"
        redirect "/login"
      end
    end
  
    before do
      unless session['user_name'] || request.path_info == '/login'
        session['request'] = request.path_info
        halt 401, %({"message" : "Access denied, please login.", "location" : "/login"}\n)
      end
      puts "Found #{session['user_name']} in session" if session['user_name']
    end

  end

  register Protection

end

