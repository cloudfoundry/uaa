require 'uaa/http'
require 'uaa/error'
require 'base64'

# Utility API for client of the UAA server.  Provides convenience
# methods to obtain and decode OAuth2 access tokens.
class Cloudfoundry::Uaa::Client

  include Cloudfoundry::Uaa::Http

  # The target (base url) of calls to the UAA server.  Default is "http://uaa.vcap.me".
  attr_writer :target
  # The client id to use if client authorization is needed (default "app")
  attr_writer :client_id
  # The client secret to use if client authorization is needed
  attr_writer :client_secret
  # The oauth scope to use if needed (default "read")
  attr_writer :scope

  def initialize
    @target = 'http://uaa.vcap.me'
    @client_id = "app"
    @client_secret = "appclientsecret"
    @scope = ["read"]
  end

  # Get the prompts (login info) required by the UAA server.  The response 
  # is a hash in the form {:name=>[<type>,<message>],...}
  def prompts()
    json_get('/login')[:prompts]
  end

  # The default prompts that can be used to elicit input for resource
  # owner password credentials (username and password).
  def default_prompts()
    {:username=>["text", "Username"], :password=>["password", "Password"]}
  end

  # Login get back an OAuth token.
  #
  # === Attributes
  #
  # * +opts+ - parameters to send, e.g.
  #   * +username+ - the username of the resource owner to login
  #   * +password+ - the password of the resource owner to login
  #   * +client_id+ - the client id (defaults to the instance attribute)
  #   * +client_secret+ - the client secret (defaults to the instance attribute)
  #   * +scope+ - the oauth scopes to request, array of String, or space-separated list
  #     (defaults to the instance attribute)
  def login(opts={})

    opts = opts.dup
 
    opts[:client_id] = @client_id unless opts[:client_id]
    opts[:client_secret] = @client_secret unless opts[:client_secret]
    opts[:scope] = @scope unless opts[:scope]
    opts[:grant_type] = "password" unless opts[:grant_type]
    if opts[:grant_type]=="password" then
      username = opts[:username]
      password = opts[:password]
      raise Cloudfoundry::Uaa::PromptRequiredError.new(default_prompts) if (username.nil? || password.nil?)
    end

    opts[:scope] = join_array(opts[:scope]) if opts[:scope]

    headers = {'Content-Type'=>"application/x-www-form-urlencoded", 
      'Accept'=>"application/json", 
      'Authorization'=>client_auth(opts)}

    opts.delete(:client_secret) # don't send secret in post data
    form_data = opts.map{|k,v| "#{k}=#{v}"}.join('&')

    status, body, headers = request(:post, '/oauth/token', form_data, headers)
    json_parse(body)[:access_token]

  end

  # Decode the contents of an opaque token obtained from the target UAA.
  #
  # === Attributes
  #
  # * +token+ - mandatory: the token to decode (e.g. obtained from #login)
  # * +opts+ - optional: additional parameters to send, e.g.
  #   * +client_id+ - the client id (defaults to the instance attribute)
  #   * +client_secret+ - the client secret (defaults to the instance attribute)
  def decode_token(token, opts={})
    headers = {'Accept'=>"application/json", 
      'Authorization'=>client_auth(opts)}
    status, body, headers = request(:get, "/check_token?token=#{token}", nil, headers)
    result = json_parse(body)   
  end

  private

  def join_array(value)
    return value.join(" ") if value.is_a?(Array)
    value
  end

  def client_auth(opts={})
    client_id = opts[:client_id] ? opts[:client_id] : @client_id
    client_secret = opts[:client_secret] ? opts[:client_secret] : @client_secret
    auth = Base64::strict_encode64("#{client_id}:#{client_secret}")
    "Basic #{auth}"
  end

end
