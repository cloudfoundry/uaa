#-----------------------------------------------------------------------------
# Web or Native Clients (in the OAuth2 sense) would use this class to get tokens
# that they can use to get access to resources

# Client Apps that want to get access on behalf of their users to
# resource servers need to get tokens via authcode and implicit flows,
# request scopes, etc., but they don't need to process tokens. This
# class is for these use cases.

class Cloudfoundry::Uaa::TokenIssuer

  include Cloudfoundry::Uaa::Http

  def initialize(target, client_id, client_secret, scope)
    @target, @client_id, @client_secret = target, client_id, client_secret
    @scope = scope
    @target = target
  end

  def authcode_redirect_uri(callback_uri)
  # => uri string
  # save private @authcode_state, @authcode_callback_uri
  end

  def authcode_grant(callback_location_header)
  # use private @authcode_state, @authcode_callback_uri
  # => token_type, token, expires_in, granted_scopes, granted_resids, others{}, refresh_token
  # => error_response
  end

  # login prompts for use by app to collect credentials for implicit grant
  def prompts
    return @prompts if @prompts || (response = json_get('/login')) && (@prompts = response[:prompts])
    raise StandardError, "No prompts in response. Is the server running at #{@target}?"
  end

  def implicit_grant(credentials)
   #generate state, callback_uri
   #parse response in location_header, check state, callback_uri
   #=> token_type, token, expires_in, granted_scopes, granted_resids, others{}
   #=> error_response
    #begin
      #loc = URI.parse(headers[:location])
      #if (status != 302 || loc.scheme != 'vmc' || loc.host != 'implicit_grant')
        #raise BadTarget
      #end
    #rescue
      #raise BadTarget, "received invalid response from authentication target #{authen_target}"
    #end
  end

  def owner_password_grant(username, password)
    auth_header = "Basic " + Base64::strict_encode64("#{@client_id}:#{@client_secret}")
    headers = {'Content-Type'=> "application/x-www-form-urlencoded",
        'Accept'=>"application/json", 'Authorization' => auth_header}
    body = URI.encode_www_form(:grant_type => "password", :username => username, :password => password, :scope => @scope)
    @parsed_reply = json_parse_reply(*request(:post, '/oauth/token', body, headers))
    @parsed_reply[:access_token]
  end

  def client_credentials_grant
  # => token_type, token, expires_in, granted_scopes, granted_resids, others{}
  # => error_response
  end

  def refresh_token
  # => token_type, token, expires_in, granted_scopes, granted_resids, others{}
  # => error_response
  end

  def info
  # => {token_type, token, expires_in, granted_scopes, granted_resids, refresh_token, error, others, ...}
    @parsed_reply
  end

end
