# Login Sample Application

This login application is a sample for how you can set up your own custom login user interface using the UAA as a backend Identity Provider. The application also supports different openid identity providers. The application is written in ruby and uses the sinatra framework. You may choose to embed it along with your code to provide a customized look and feel for the login interface using the UAA as an identity provider and a token server to issue Oauth access tokens.

## Quick start

Start your UAA and Sample Applications

    $ git clone git@github.com:cloudfoundry/uaa.git
    $ cd uaa
    $ ./gradlew run


Verify that the uaa has started by going to http://localhost:8080/uaa

Start the sample login application

    $ cd samples/ruby-login-server
    $ bundle install
    $ bundle exec thin start
    >> Using rack adapter
    I, [2012-06-14T14:54:46.273942 #5369]  INFO -- : Using token server http://localhost:8080/uaa
    >> Thin web server (v1.3.1 codename Triple Espresso)
    >> Maximum connections set to 1024
    >> Listening on 0.0.0.0:3000, CTRL+C to stop

You can start the oauth flow with a HTTP GET request to http://localhost:3000/oauth/authorize?client_id=app&response_type=code&scope=openid&redirect_uri=http://foo.com

Login with the pre-created UAA user/password of "marissa/koala"

## Customizing the application

### Using a different token server

The back end UAA token server URL can be customized by setting the UAA_TOKEN_SERVER environment variable
This application also uses the login client to support logging in with authenticated email addresses from OpenID providers. The secret for the login client can be customized by 
setting the LOGIN_CLIENT_SECRET environment variable

For details on the login client, please refer to the UAA.

Each of these variables default to the values for a locally hosted UAA.

### Customizing the user interface

There are two ruby templates that can be customized for look and feel to match your application. These are login.erb used to display the login interface and confirm.erb used to display the authorization confirmation page.

### Logging

Before using this as a sample, please configure the application logging to ensure that no confidential information is logged.

## Playing with the entire flow

You may write a simple sinatra client application to test the end to end flow as follows. This client also uses application defaults for a locally hosted UAA. It logs the user into the UAA and displays a UAA access token if the login succeeds

    require 'sinatra'
    require 'yajl'
    require 'restclient'
    require 'base64'

    LOGIN_SERVER_URL = ENV['LOGIN_SERVER_URL'] || "http://localhost:3000"
    UAA_TOKEN_SERVER = ENV['UAA_TOKEN_SERVER'] || "http://localhost:8080/uaa"
    CLIENT_SECRET = ENV['CLIENT_SECRET'] || "appclientsecret"

    get '/' do
      "<html><body><a href=\"#{LOGIN_SERVER_URL}/oauth/authorize?client_id=app&response_type=code&scope=openid&redirect_uri=#{request.scheme}://#{request.host_with_port}/done\"\">Login</a></body></html>"
    end

    get '/done' do
      code = params[:code]
      $logger = Logger.new(STDOUT)
      RestClient.log = $logger
      response = RestClient.post("#{UAA_TOKEN_SERVER}/oauth/token", {"grant_type" => "authorization_code", "code" => "#{code}", "redirect_uri" => "#{request.scheme}://#{request.host_with_port}/done"}, {:accept => :json, :authorization => "Basic #{Base64.strict_encode64("app:#{CLIENT_SECRET}")}"}) \
          {|response, request, result, &block| response}
      puts "#{response.body.inspect}"

      begin
        access_token = Yajl::Parser.new.parse(response.body)["access_token"]
        decoded_token = Base64.decode64(access_token.split('.')[1])
        "Access Token from UAA is #{access_token} \
          <br /><br />Decoded token is #{decoded_token} \
          <br /><br /><a href=\"#{LOGIN_SERVER_URL}/logout\">Logout</a>"
      rescue => e
        puts "#{e.backtrace}"
        "Could not fetch access token"
      end
    end
