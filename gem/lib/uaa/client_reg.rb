#--
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
#++

require 'uaa/http'

module CF::UAA

# This class is for apps that need to manage Client registrations within the UAA.
class ClientReg

  include Http

  MULTI_VALUED = [:scope, :authorized_grant_types, :authorities, :redirect_uri]

  def self.multivalues_to_arrays!(info)
    MULTI_VALUED.each_with_object(info) { |v, o| o[v] = Util.arglist(o[v]) if o[v] }
  end

  def self.multivalues_to_strings!(info)
    MULTI_VALUED.each_with_object(info) { |v, o| o[v] = Util.strlist(o[v]) if o[v] }
  end

  # the auth_header parameter refers to a string that can be used in an
  # authorization header. For oauth with jwt tokens this would be something
  # like "bearer xxxx.xxxx.xxxx". The Token class returned by TokenIssuer
  # provides an auth_header method for this purpose.
  def initialize(target, auth_header)
    @target, @auth_header = target, auth_header
  end

  # takes a hash of fields currently supported by the uaa:
  #     client_id (required),
  #     client_secret,
  #     scope (array of strings or space or comma separated fields),
  #     authorized_grant_types (array of strings or space or comma separated fields),
  #     authorities (array of strings or space or comma separated fields),
  #     access_token_validity (integer)
  #     refresh_token_validity (integer)
  #     redirect_uri (array of strings or space or comma separated fields),

  def create(info)
    info = Util.hash_keys(info)
    raise ArgumentError, "a client registration must specify a unique client id" unless info[:client_id]
    info = self.class.multivalues_to_arrays! info
    json_parse_reply *json_post("/oauth/clients", info, @auth_header)
  end

  def update(info)
    info = Util.hash_keys(info)
    raise ArgumentError, "a client registration update must specify a unique client id" unless info[:client_id]
    info = self.class.multivalues_to_arrays! info
    json_parse_reply *json_put("/oauth/clients/#{URI.encode(info[:client_id])}", info, @auth_header)
  end

  def get(id); json_get "/oauth/clients/#{URI.encode(id)}", @auth_header end
  def delete(id); http_delete "/oauth/clients/#{URI.encode(id)}", @auth_header end
  def list; json_get "/oauth/clients", @auth_header end

  def change_secret(client_id, new_secret, old_secret = nil)
    req = { secret: new_secret }
    req[:oldSecret] = old_secret if old_secret
    json_parse_reply(*json_put("/oauth/clients/#{URI.encode(client_id)}/secret", req, @auth_header))
  end

end

end
