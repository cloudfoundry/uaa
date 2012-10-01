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

require 'rest_client'
require 'eventmachine'
require 'em-http'
require 'fiber'
require 'base64'
require 'uaa/util'

module CF::UAA

class BadTarget < RuntimeError; end
class NotFound < RuntimeError; end
class BadResponse < RuntimeError; end
class InvalidToken < RuntimeError; end
class HTTPException < RuntimeError; end
class TargetError < RuntimeError
  attr_reader :info
  def initialize(error_info = {})
    @info = error_info
  end
end

# Utility accessors and methods for objects that want to access JSON web APIs.
module Http

  attr_accessor :proxy, :async
  def logger=(logr); @logger = logr end
  def logger ; @logger ||= Util.default_logger end
  def trace? ; @logger && @logger.respond_to?(:trace?) && @logger.trace? end

  def self.basic_auth(name, password)
    "Basic " + Base64::strict_encode64("#{name}:#{password}")
  end

  # json helpers

  def add_auth_header(auth, headers) headers[:authorization] = auth if auth; headers end

  def json_get(target, path = nil, authorization = nil, headers = {})
    json_parse_reply(*http_get(target, path,
        add_auth_header(authorization, headers.merge(accept: "application/json"))))
  end

  def json_post(target, path, body, authorization, headers = {})
    http_post(target, path, body.to_json,
        add_auth_header(authorization, headers.merge(content_type: "application/json")))
  end

  def json_put(target, path, body, authorization = nil, headers = {})
    http_put(target, path, body.to_json,
        add_auth_header(authorization, headers.merge(content_type: "application/json")))
  end

  def json_patch(target, path, body, authorization = nil, headers = {})
    http_patch(target, path, body.to_json,
        add_auth_header(authorization, headers.merge(content_type: "application/json")))
  end

  def json_parse_reply(status, body, headers)
    unless [200, 201, 204, 400, 401, 403].include? status
      raise (status == 404 ? NotFound : BadResponse), "invalid status response: #{status}"
    end
    if body && !body.empty? && (headers && headers[:content_type] !~ /application\/json/i || status == 204)
      raise BadResponse, "received invalid response content or type"
    end
    parsed_reply = Util.json_parse(body)
    if status >= 400
      raise parsed_reply && parsed_reply[:error] == "invalid_token" ?
          InvalidToken : TargetError.new(parsed_reply), "error response"
    end
    parsed_reply
  rescue JSON::ParserError
    raise BadResponse, "invalid JSON response"
  end

  # HTTP helpers

  def http_get(target, path = nil, headers = {}) request(target, :get, path, nil, headers) end
  def http_post(target, path, body, headers = {}) request(target, :post, path, body, headers) end
  def http_put(target, path, body, headers = {}) request(target, :put, path, body, headers) end
  def http_patch(target, path, body, headers = {}) request(target, :patch, path, body, headers) end

  def http_delete(target, path, authorization)
    status = request(target, :delete, path, nil, authorization: authorization)[0]
    unless [200, 204].include?(status)
      raise (status == 404 ? NotFound : BadResponse), "invalid response from #{path}: #{status}"
    end
  end

  def request(target, method, path, payload = nil, headers = {})
    headers = headers.dup
    headers[:proxy_user] = @proxy if @proxy unless headers[:proxy_user]
    headers[:accept] = headers[:content_type] if headers[:content_type] && !headers[:accept]

    req = { method: method, url: "#{target}#{path}", payload: payload,
        headers: Util.hash_keys(headers, :todash) }

    logger.debug { "---> #{@async ? 'async' : ''}\nrequest: #{method} #{req[:url]}\n" +
        "headers: #{req[:headers]}\n#{'body: ' + Util.truncate(payload.to_s, trace? ? 50000 : 50) if payload}" }

    status, body, response_headers = async ? perform_ahttp_request(req) : perform_http_request(req)

    logger.debug { "<---\nresponse: #{status}\nheaders: #{response_headers}\n" +
        "#{'body: ' + Util.truncate(body.to_s, trace? ? 50000: 50) if body}" }

    [status, body, Util.hash_keys(response_headers, :undash)]

  rescue Exception => e
    e.message.replace "Target #{target}, #{e.message}"
    logger.debug { "<---- no response due to exception: #{e}" }
    raise e
  end

  private

  def perform_http_request(req)
    RestClient::Request.execute(req) { |resp, req| [resp.code, resp.body, resp.headers] }
  rescue URI::Error, SocketError, SystemCallError => e
    raise BadTarget, "error: #{e.message}"
  rescue RestClient::Exception, Net::HTTPBadResponse => e
    raise HTTPException, "HTTP exception: #{e.class}: #{e}"
  end

  def perform_ahttp_request(req)
    f = Fiber.current
    connection = EventMachine::HttpRequest.new(req[:url], connect_timeout: 10, inactivity_timeout: 10)
    client = connection.setup_request(req[:method].to_sym, head: req[:headers], body: req[:payload])

    # This check is for proper error handling with em-http-request 1.0.0.beta.3
    if defined?(EventMachine::FailedConnection) && connection.is_a?(EventMachine::FailedConnection)
      raise BadTarget, "HTTP connection setup error: #{client.error}"
    end

    client.callback { f.resume [client.response_header.http_status, client.response, client.response_header] }
    client.errback { f.resume [:error, client.error] }
    result = Fiber.yield
    if result[0] == :error
      raise BadTarget, "connection failed" unless result[1] && result[1] != ""
      raise BadTarget, "connection refused" if result[1].to_s =~ /ECONNREFUSED/
      raise BadTarget, "unable to resolve address" if /unable.*server.*address/.match result[1]
      raise HTTPException, result[1]
    end
    result
  end

end

end
