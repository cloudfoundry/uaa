require 'uaa/http'
require 'uaa/error'
require 'base64'
require 'uri'

# Utility API for client of the UAA server.  Provides convenience
# methods to obtain and decode OAuth2 access tokens.
class Cloudfoundry::Uaa::Client

  include Cloudfoundry::Uaa::Http

  # The target (base url) of calls to the UAA server.  Default is "http://uaa.vcap.me".
  attr_writer :target
  # The client id to use if client authorization is needed (default "vmc")
  attr_writer :client_id
  # The client secret to use if client authorization is needed
  attr_writer :client_secret
  # The oauth scope to use if needed (default "read")
  attr_writer :scope
  # The grant type to use when logging in (default "implicit")
  attr_writer :grant_type

  def initialize
    @target = 'http://uaa.vcap.me'
    @client_id = "vmc"
    @client_secret = nil
    @grant_type = "implicit"
    @scope = ["read"]
    @redirect_uri = "uri:oauth:token"
  end

  # Get the prompts (login info) required by the UAA server.  The response 
  # is a hash in the form {:name=>[<type>,<message>],...}
  def prompts
    return @prompts if @prompts # TODO: reset prompts when the target changes?
    begin
      response = json_get('/login')
    rescue
      # Ignore
    end
    raise StandardError, "No response from prompts endpoint. Is the server running at #{@target}?" unless response
    @prompts ||= response[:prompts]
    raise StandardError, "No prompts available. Is the server running at #{@target}?" unless @prompts
    @prompts
  end

  # The default prompts that can be used to elicit input for resource
  # owner password credentials (username and password).
  def default_prompts
    {:username=>["text", "Username"], :password=>["password", "Password"]}
  end

  # Login get back an OAuth token. By default the UAA
  #
  # === Attributes
  #
  # * +opts+ - parameters to send, e.g.
  #   * +client_id+ - the client id (defaults to the instance attribute)
  #   * +grant_type+ - the OAuth2 grant type (default to the instance attribute)
  #   * +client_secret+ - the client secret (defaults to the instance attribute)
  #   * +scope+ - the oauth scopes to request, array of String, or comma- or space-separated list (defaults to "read")
  #   * +credentials+ - a hash of credentials to be passed to the server as a JSON literal (with :grant_type=>"implicit")
  #   * +username+ - the username of the resource owner to login (with :grant_type="password")
  #   * +password+ - the password of the resource owner to login (with :grant_type="password")
  #     (defaults to the instance attribute)
  # 
  # === Implicit Grant
  #
  # The default grant type is "implicit" which is used by vmc and
  # other untrusted clients.  The UAA server authenticates the user in
  # that case using the data provided in the +credentials+ option.
  #
  # As a convenience the +credentials+ default to the +username+ and
  # +password+ if those are provided.
  #
  # If +credentials+ are not provided, or if +username+ is provided
  # without a +password+ then a Cloudfoundry::Uaa::PromptRequiredError
  # is raised.
  def login(opts={})

    opts = opts.dup
 
    opts[:client_id] ||= @client_id
    opts[:client_secret] ||= @client_secret if @client_secret
    opts[:scope] ||= @scope
    grant_type = opts[:grant_type] || @grant_type
    opts[:grant_type] = grant_type

    username = opts[:username]
    password = opts[:password]
    if grant_type=="password" then
      raise Cloudfoundry::Uaa::PromptRequiredError.new(default_prompts) if (username.nil? || password.nil?)
    else
      if prompts_require_username_and_password? && username && password then
        opts[:credentials] = {:username=>username, :password=>password}
      end
      raise Cloudfoundry::Uaa::PromptRequiredError.new(prompts) unless opts[:credentials]
      # make sure they don't get used as request or form params unless we want them to
      opts.delete :username
      opts.delete :password
    end

    if grant_type!="client_credentials" && grant_type!="password" then
      opts[:redirect_uri] ||= @redirect_uri
    end

    opts[:scope] = join_array(opts[:scope]) if opts[:scope]

    headers = {'Content-Type'=>"application/x-www-form-urlencoded", 
      'Accept'=>"application/json"}
    add_client_auth(grant_type, headers, opts)

    case grant_type
    when "implicit"
      url = '/oauth/authorize'
      opts[:response_type] = "token"
      opts.delete :grant_type # don't send grant type
    when "authorization_code"
      url = '/oauth/authorize'
      opts[:response_type] = "code"
      opts.delete :grant_type # don't send grant type
    else
      url = '/oauth/token'
    end

    opts.delete :client_secret # don't send secret in post data
    opts.delete :verbose

    form_data = opts.map{|k,v| value=v.is_a?(Hash) ? v.to_json : v; "#{k}=#{value}"}.join('&')

    status, body, headers = request(:post, url, form_data, headers)
    if (grant_type=="implicit") then
      token = extract_implicit_token(headers)
    end
    return token if token

    json = json_parse(body)
    return json if !json

    return json[:access_token]

  end

  # Decode the contents of an opaque token obtained from the target UAA.
  #
  # === Attributes
  #
  # * +token+ - mandatory: the token to decode (e.g. obtained from #login)
  # * +opts+ - optional: additional parameters to send, e.g.
  #   * +client_id+ - the client id (defaults to the instance attribute)
  #   * +client_secret+ - the client secret (defaults to the instance attribute)
  #
  # Note that the default client (vmc) is not authorized to decode
  # tokens, so callers will need to change the default or provide
  # explicit values in the options. Authoeized clients must be
  # pre-registered with the server.
  def decode_token(token, opts={})
    headers = {'Accept'=>"application/json", 
      'Authorization'=>client_auth(opts)}
    status, body, headers = request(:get, "/check_token?token=#{URI.escape(token)}", nil, headers)
    result = json_parse(body)   
  end

  private

  def prompts_require_username_and_password?
    prompts.has_key?(:username) && prompts.has_key?(:password) && prompts.length==2
  end

  def join_array(value)
    return value.join(" ") if value.is_a?(Array)
    value
  end

  def add_client_auth(grant_type, headers={}, opts={})
    if (grant_type!="implicit") then
      auth = client_auth(opts)
      headers['Authorization'] = auth if auth
    end
  end

  def client_auth(opts={})
    client_id = opts[:client_id] ? opts[:client_id] : @client_id
    client_secret = opts[:client_secret] ? opts[:client_secret] : @client_secret
    if client_id || client_secret then
      auth = Base64::strict_encode64("#{client_id}:#{client_secret}")
      "Basic #{auth}"
    end
  end

  def extract_implicit_token(headers={})
    return nil unless headers
    location = headers['Location'] || headers['location'] || headers[:location]
    parts = location.split('#')
    if parts.length > 1
      values=parts[1].split('&')
      token = values.each do |kv|
        k,v = kv.split('=')
        return v if k=="access_token"
      end
    end
    return nil
  end

end
