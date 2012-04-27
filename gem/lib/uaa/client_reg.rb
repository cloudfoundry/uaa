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

  def create(id, secret, scopes, resource_ids, grant_types, roles, redirect_uris = nil)
    raise ArgumentError, "uaa must have client secret on client registration" unless secret
    request = { client_id: id, secret: secret, scope: Util.arglist(scopes),
        resource_ids: Util.arglist(resource_ids),
        authorized_grant_types: Util.arglist(grant_types), authorities: Util.arglist(roles) }
    request[:redirect_uri] = Util.arglist(redirect_uris) if redirect_uris

    request[:client_sercet] = secret # TODO: remove this after uaa is fixed.

    status, body, headers = json_post("/oauth/clients", request, @auth_header)
    raise BadResponse, "invalid response from #{@target}: #{status}" unless status == 201
  end

  def update(id, secret, scopes, resource_ids, grant_types, roles, redirect_uris = nil)
    raise ArgumentError, "uaa must have client secret on client update" unless secret
    request = { client_id: id, secret: secret, scope: Util.arglist(scopes),
        resource_ids: Util.arglist(resource_ids),
        authorized_grant_types: Util.arglist(grant_types), authorities: Util.arglist(roles) }

    request[:client_sercet] = secret # TODO: remove this after uaa is fixed.

    request[:redirect_uri] = Util.arglist(redirect_uris) if redirect_uris
    status, body, headers = json_put("/oauth/clients/#{URI.encode(id)}", request, @auth_header)
  end

  def get(id)
    json_get("/oauth/clients/#{URI.encode(id)}", @auth_header)
  end

  def delete(id)
    unless (status = http_delete("/oauth/clients/#{URI.encode(id)}", @auth_header)) == 200
      raise (status == 404 ? NotFound : BadResponse), "invalid response from #{@target}: #{status}"
    end
  end

end

end
