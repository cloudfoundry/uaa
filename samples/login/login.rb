require 'sinatra/base'
require 'restclient'
require 'yajl'
require 'logger'
require 'base64'

# The LoginApplication class handles the oauth
# authorization flow for the CloudFoundry UAA
class LoginApplication < Sinatra::Base
  enable :sessions

  # URL of the uaa token server
  UAA_TOKEN_SERVER = ENV['UAA_TOKEN_SERVER'] || "http://localhost:8080/uaa"
  # Client secret of the login client. The login client allows this
  # application to authenticate to the token endpoint to get an access token
  # for a pre-authenticated email address (for the case when a pre-authenticated
  # email address is received by this application from an OpenID provider)
  LOGIN_CLIENT_SECRET = ENV['LOGIN_CLIENT_SECRET'] || "loginsecret"
 
  # Handles requests to the /login endpoint.
  # If an authenticated user session already exists with the authorization server, 
  # the user is redirected to a confimation page
  get '/login' do
    pass unless params[:email].nil?

    # If there is already a session with the uaa, the user has been authenticated
    if uaa_session?(request).nil?
      erb :login
    else
      redirect '/confirm'
    end
  end

  # The start of the oauth flow for the client application
  get '/oauth/authorize' do
    if params.nil? || params.empty?
      halt 404
    end

    # Store the request parameters in session
    [:client_id, :response_type, :scope, :redirect_uri, :state].each{|param| session[param] = params[param.to_s]}
    $logger.debug("Saving request parameters #{session.inspect}")

    # Redirect the user to the login page if no session
    # is available with the uaa
    if uaa_session?(request).nil?
      redirect '/login'
    else
      redirect '/confirm'
    end
  end

  # Common login flow for incoming username and password credentials
  # or incoming authenticated email addresses
  login = lambda do
    username = request[:username]
    password = request[:password]

    uaa_response = nil
    unless username.nil? && password.nil?
      # Post the credentials and get a session with the uaa. Save the uaa cookie
      uaa_response = post("#{UAA_TOKEN_SERVER}/login.do", \
                           {"username" => username, "password" => password})
      $logger.debug "#{uaa_response.headers.inspect}"
    else
      # Get the email address from the openid provider and ask for authorization directly
      email = session[:authenticated_email]
      $logger.debug "authenticated email address #{email}"
      # Post the credentials and get a session with the uaa. Save the uaa cookie
      uaa_response = post_to_authorize({"login" => "#{Yajl::Encoder.encode("username" => email)}"}, \
                                       {:authorization => "bearer #{login_access_token()}"})
      $logger.debug "#{uaa_response.headers.inspect}"
    end

    # If the response from the UAA is a redirect ending in error=true, authentication has failed
    if uaa_response.headers[:location] =~ /\?error=true/
      redirect '/login?error=true'
    end

    if uaa_response.nil?
      $logger.debug("Could not establish session with the uaa")
      redirect '/login?error=true'
    end

    # Maintain the cookie with the uaa
    uaa_cookie = uaa_response.cookies["JSESSIONID"]
    $logger.debug "UAA Cookie #{uaa_cookie}"
    response.set_cookie("uaa_cookie", uaa_cookie)

    redirect '/confirm'
  end

  # A similar authorization flow is implemented for the uaa as well as openid flows
  get '/authenticatedlogin', &login
  post '/login', &login

  # Handles authorization confirmation flow
  get '/confirm' do
    cookie = uaa_session?(request)
    $logger.debug("Current values in session #{session.inspect}")
    unless cookie.nil?
      [:client_id, :response_type, :scope, :redirect_uri].each do |parameter| \
        unless session[:parameter].nil?
          halt 400, "Invalid request. User authenticated but unable to find \"#{parameter}\" parameter \
                     from request. Please see README for directions."
        end
      end
      # Maintaining the UAA cookie from the successful login to the uaa,
      # post to the /oauth/authorize endpoint to get the confirmation data
      request_params = {"client_id" => session[:client_id],
                        "response_type" => session[:response_type],
                        "scope" => session[:scope],
                        "redirect_uri" => session[:redirect_uri]}
      request_params["state"] = session[:state] unless session[:state].nil?
      uaa_response = post_to_authorize(request_params, {:cookies => { :JSESSIONID => cookie}})
      $logger.debug "#{uaa_response.inspect}"
      case uaa_response.code
        when 200
          confirmation_info = Yajl::Parser.new.parse(uaa_response.body)
          $logger.debug "#{confirmation_info.inspect}"
          session[:confirm_key] = (confirmation_info["options"]["confirm"]["key"] \
            if confirmation_info["options"] && confirmation_info["options"]["confirm"]) || "user_oauth_approval"
              
          erb :confirm, :locals => {:client_id => confirmation_info["auth_request"]["authorizationParameters"]["client_id"], \
                                    :scopes => confirmation_info["auth_request"]["authorizationParameters"]["scope"]}
        when 302
          # Access confirmation not required, get the code.
          $logger.debug "#{uaa_response.headers[:location]}"

          redirect uaa_response.headers[:location]
        else
          halt 500, "error from the token server #{uaa_response.inspect}"
      end
    else
      halt 500, "invalid state"
    end
  end

  # User confirms / denies authorization
  post '/confirm' do
    choice = params[:choice]
    $logger.debug "#{choice}"

    target = '/login'

    # User confirms authorization
    if choice == "yes"
      cookie = request.cookies['uaa_cookie']

      # Post confirmation to the uaa and redirect to the target
      request_params = {"client_id" => session[:client_id],
                        "response_type" => session[:response_type],
                        "scope" => session[:scope],
                        "redirect_uri" => session[:redirect_uri],
                        session[:confirm_key] => "true"}
      request_params[:state] = session[:state] unless session[:state].nil?
      uaa_response = post_to_authorize(request_params, {:cookies => { :JSESSIONID => cookie}})
      $logger.debug "#{uaa_response.headers[:location]}"
      target = uaa_response.headers[:location]
    else
      cleanup(response)
    end

    redirect target
  end

  get '/logout' do
    cleanup(response)
  end

  helpers do
    def uaa_session?(request)
      cookie = request.cookies['uaa_cookie']
      $logger.debug("Found uaa session cookie #{cookie}")
      unless cookie.nil?
        $logger.debug "cookie value #{cookie}"
        response = post_to_authorize(nil, {:cookies => { :JSESSIONID => cookie}})
        $logger.debug("uaa_session #{response.headers.inspect}")
        if response.code == 302 && response.headers[:location] =~ /\/login/
          cookie = nil
        end
      end
      cookie
    end

    def cleanup(response)
      response.delete_cookie('uaa_cookie')
      session.clear
    end

    def post_to_authorize(request_params, headers)
      headers = headers.merge(:accept => :json)

      $logger.debug("Headers to post to authorize #{headers}")

      post("#{UAA_TOKEN_SERVER}/oauth/authorize", request_params, headers)
    end

    def login_access_token
      # Get an access token for the login client
      login_response = post("#{UAA_TOKEN_SERVER}/oauth/token", \
                             {"response_type" => "token", "grant_type" => "client_credentials"}, \
                             {:accept => :json, :authorization => "Basic #{Base64.strict_encode64("login:#{LOGIN_CLIENT_SECRET}")}"})
      $logger.debug "#{login_response.body.inspect}"
      access_token = Yajl::Parser.new.parse(login_response.body)["access_token"]
    end

    def post(url, content, headers = nil)
      begin
        response = RestClient.post(url, content, headers) \
          {|response, request, result, &block| response}
      rescue => e
        $logger.error("Error connecting to #{url}, #{e.backtrace}")
        halt 500, "UAA unavailable."
      end
    end
  end

  configure :development do
    $logger = Logger.new(STDOUT)
    RestClient.log = $logger
    $logger.info("Using token server #{UAA_TOKEN_SERVER}")
  end

  configure :production do
    $logger = Logger.new(STDOUT)
    $logger.info("Using token server #{UAA_TOKEN_SERVER}")
  end

  get '/' do
    redirect '/login'
  end

end
