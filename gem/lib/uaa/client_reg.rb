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

  # the auth_header parameter refers to a string that can be used in an
  # authorization header. For oauth with jwt tokens this would be something
  # like "bearer xxxx.xxxx.xxxx". The Token class returned by TokenIssuer
  # provides an auth_header method for this purpose.
  def initialize(target, auth_header, debug = false)
    @target, @auth_header, @debug = target, auth_header, debug
  end

  # takes a hash of fields currently supported by the uaa:
  #     client_id (required),
  #     secret,
  #     scope (array of strings or space or comma separated fields),
  #     resource_ids (array of strings or space or comma separated fields),
  #     authorized_grant_types (array of strings or space or comma separated fields),
  #     authorities (array of strings or space or comma separated fields),
  #     access_token_validity (integer)
  #     refresh_token_validity (integer)
  #     redirect_uri (array of strings or space or comma separated fields),

  def create(info)
    info = Util.rubyize_keys(info)
    raise ArgumentError, "a client registration must specify a unique client id" unless info[:client_id]
    info = fixup_reg_fields info
    json_parse_reply *json_post("/oauth/clients", info, @auth_header)
  end

  def update(info)
    info = Util.rubyize_keys(info)
    raise ArgumentError, "a client registration update specify a unique client id" unless info[:client_id]
    info = fixup_reg_fields info
    json_parse_reply *json_put("/oauth/clients/#{URI.encode(info[:client_id])}", info, @auth_header)
  end

  def get(id)
    json_get("/oauth/clients/#{URI.encode(id)}", @auth_header)
  end

  def delete(id)
    unless (status = http_delete("/oauth/clients/#{URI.encode(id)}", @auth_header)) == 200
      raise (status == 404 ? NotFound : BadResponse), "invalid response from #{@target}: #{status}"
    end
  end

  def list
    json_get("/oauth/clients", @auth_header)
  end

  def change_secret(id, old_secret, new_secret)
 #PUT /oauth/clients/foo/password
#{
  #oldSecret: fooclientsecret,
  #secret: newclientsceret
#}
  end

  private

  def fixup_reg_fields(info)
    [:scope, :resource_ids, :authorized_grant_types, :authorities, :redirect_uri].each do |v|
      info[v] = Util.arglist(info[v]) if info[v]
    end
    info
  end

end

end
