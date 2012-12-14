$:.unshift(".")

require 'login'
require 'openid_login'

map "/openid" do
  run OpenIdLoginApplication.new
end

map "/" do
  run LoginApplication.new
end
