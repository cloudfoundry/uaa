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
class HTTPException < RuntimeError; end
class TargetError < RuntimeError
  attr_reader :info
  def initialize(error_info = {})
    @info = error_info
  end
end

# Utility accessors and methods for objects that want to access JSON web APIs.
module Http

  attr_accessor :debug, :proxy, :async, :logger
  attr_reader :target

  def self.basic_auth(name, password)
    "Basic " + Base64::strict_encode64("#{name}:#{password}")
  end

  private

  def json_get(url, authorization = nil)
    json_parse_reply(*http_get(url, 'application/json', authorization))
  end

  def json_parse_reply(status, body, headers)
    unless [200, 201, 400, 401].include? status
      raise (status == 404 ? NotFound : BadResponse), "invalid status response from #{@target}: #{status}"
    end
    if body && !body.empty? && headers && headers[:content_type] !~ /application\/json/i
      raise BadResponse, "received invalid response content type from #{@target}"
    end
    parsed_reply = Util.json_parse(body)
    raise TargetError.new(parsed_reply), "error response from #{@target}" if [400, 401].include? status
    parsed_reply
  rescue JSON::ParserError
    raise BadResponse, "invalid JSON response from #{@target}"
  end

  def json_post(url, body, authorization)
    http_post(url, body.to_json, "application/json", authorization)
  end

  def json_put(url, body, authorization)
    http_put(url, body.to_json, "application/json", authorization)
  end

  # HTTP helpers

  def http_get(path, content_type = nil, authorization = nil)
    headers = {}
    headers[:content_type] = content_type if content_type
    headers[:authorization] = authorization if authorization
    request(:get, path, nil, headers)
  end

  def http_post(path, body, content_type, authorization)
    request(:post, path, body, content_type: content_type, authorization: authorization)
  end

  def http_put(path, body, content_type, authorization)
    request(:put, path, body, content_type: content_type, authorization: authorization)
  end

  def http_delete(path, authorization)
    request(:delete, path, nil, authorization: authorization)[0]
  end

  def request(method, path, payload = nil, headers = {})
    headers = headers.dup
    headers[:proxy_user] = @proxy if @proxy unless headers[:proxy_user]
    headers[:accept] = headers[:content_type] if headers[:content_type] && !headers[:accept]

    raise BadTarget, "Target must be set before executing a request" unless @target

    req = { method: method, url: "#{@target}#{path}", payload: payload,
        headers: headers, :multipart => true }
    if debug
      trace "--->"
      trace "request: #{method} #{req[:url]}"
      trace "headers: #{headers}"
      trace "body: #{Util.truncate(payload.to_s, 100)}" if payload
      trace "async: #{async.inspect}"
    end
    status, body, response_headers = async ? perform_ahttp_request(req) : perform_http_request(req)
    if debug
      trace "<---"
      trace "response: #{status}"
      trace "headers: #{response_headers}"
      trace "body: #{Util.truncate(body.to_s, 100)}" if body
    end
    [status, body, response_headers]

  rescue Exception => e
    trace "<---- no response due to exception (#{e})" if debug
    raise
  end

  def perform_http_request(req)
    RestClient.proxy = proxy_uri.to_s if proxy_uri = URI.parse(req[:url]).find_proxy()
    req[:headers] = Util.unrubyize_keys(req[:headers])
    result = nil
    RestClient::Request.execute(req) do |response, request|
      result = [ response.code, response.body, Util.rubyize_keys(response.headers) ]
    end
    result

  rescue URI::Error, SocketError, SystemCallError => e
    raise BadTarget, "Cannot access target (#{e.message})"
  rescue RestClient::Exception, Net::HTTPBadResponse => e
    raise HTTPException, "HTTP exception: #{e.class}: #{e}"
  end

  def perform_ahttp_request(req)
    f = Fiber.current
    connection = EventMachine::HttpRequest.new(req[:url], connect_timeout: 10, inactivity_timeout: 10)
    client = connection.setup_request(req[:method].to_sym,
        head: Util.unrubyize_keys(req[:headers]), body: req[:payload])

    # This condition only works with em-http-request 1.0.0.beta.3
    raise BadTarget, "HTTP connection setup error: #{client.error}" if connection.is_a? EventMachine::FailedConnection

    client.callback { f.resume [client.response_header.http_status, client.response,
        Util.rubyize_keys(client.response_header)] }
    client.errback { f.resume [:error, client.error] }
    result = Fiber.yield
    if result[0] == :error
      raise BadTarget, "connection failed" unless result[1] && result[1] != ""
      raise HTTPException, result[1]
    end
    result
  end

  def trace(string)
    logger ? logger.debug(string) : puts(string)
  end

end

end
