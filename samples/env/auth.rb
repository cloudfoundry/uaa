require 'rubygems'
require 'oauth2'
require 'json'
require "sinatra/base"

module Sinatra

  module Auth

    def client
      OAuth2::Client.new('tonr', nil, {:site => 'http://localhost:8080', :authorize_path => '/auth/oauth/user/authorize', :access_token_path => '/auth/oauth/authorize'})
    end
    
    get '/auth' do
      redirect client.web_server.authorize_url(
        :redirect_uri => redirect_uri,
        :scope => 'none',
        :target_uri => redirect_uri('/env')
      )
    end
    
    get '/auth/callback' do
      access_token = client.web_server.get_access_token(params[:code], :redirect_uri => redirect_uri)
      puts(access_token.inspect)
      access_token.get('/api/photos')
    end
    
    def redirect_uri(path = '/auth/callback')
      uri = URI.parse(request.url)
      puts(request.inspect)
      uri.path = path
      uri.query = nil
      uri.to_s
    end

  end

  helpers Auth

end

