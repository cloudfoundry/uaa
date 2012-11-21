require 'sinatra/base'
require 'logger'
require 'pathname'
require 'openid'
require 'openid/extensions/ax'
require 'openid/store/filesystem'

# The OpenIdLoginApplication class handles the oauth
# authorization flow for OpenID providers
class OpenIdLoginApplication < Sinatra::Base
  enable :sessions

  # Start of the openid flow
  get '/start' do
    begin
      identifier = params[:openid_identifier]
      if identifier.nil?
        $logger.error("No identifier found")
        redirect '/login?error=true'
      end
      oidreq = consumer.begin(identifier)
    rescue OpenID::OpenIDError => e
      $logger.error "Discovery failed for #{identifier}: #{e}"
      redirect '/login?error=true'
    end

    # Fetch the email address from the openid provider
    fetch_request = OpenID::AX::FetchRequest.new
    fetch_request.add(OpenID::AX::AttrInfo.new("http://axschema.org/contact/email", "email", true))
    oidreq.add_extension(fetch_request)

    url = server_url(request)
    return_to = "#{url}/openid/complete"
    realm = "#{url}"

    redirect oidreq.redirect_url(realm, return_to)
  end

  # End of the openid flow
  get '/complete' do
    oidresp = consumer.complete(params, request.url)
    $logger.debug("oidresp #{oidresp.inspect}")
    case oidresp.status
    when OpenID::Consumer::FAILURE
      if oidresp.display_identifier
        $logger.error("Verification of #{oidresp.display_identifier}"\
                         " failed: #{oidresp.message}")
      else
        $logger.error("Verification failed: #{oidresp.message}")
      end
    when OpenID::Consumer::SUCCESS
      $logger.info("Verification of #{oidresp.display_identifier}"\
                         " succeeded.")

      email_extension = oidresp.extension_response("http://openid.net/srv/ax/1.0", false)
      email = email_extension["value.email"]
      $logger.debug("authenticated email from openid provider #{email}")
      session[:authenticated_email] = email
      redirect "/authenticatedlogin"
    when OpenID::Consumer::SETUP_NEEDED
      $logger.error("Immediate request failed - Setup Needed")
    when OpenID::Consumer::CANCEL
      $logger.error("OpenID transaction cancelled.")
    else
      $logger.error("Unknown error #{oidresp.status.inspect}")
    end
    redirect '/login?error=true'
  end

  helpers do
    def server_url(request)
      "#{request.scheme}://#{request.host_with_port}"
    end
  end

  configure :development do
    $logger = Logger.new(STDOUT)
  end

  configure :production do
    $logger = Logger.new(STDOUT)
  end

  private

  def consumer
    if @consumer.nil?
      dir = Pathname.new(File.dirname( __FILE__)).join('db').join('cstore')
      store = OpenID::Store::Filesystem.new(dir)
      @consumer = OpenID::Consumer.new(session, store)
    end
    return @consumer
  end
end
