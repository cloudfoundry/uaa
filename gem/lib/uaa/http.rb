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

require 'json/pure'
require 'open-uri'
require 'rest_client'
require 'eventmachine'
require 'em-http'
require 'fiber'

module CF
  module UAA
    class BadTarget < RuntimeError; end
    class NotFound < RuntimeError; end
    class BadResponse < RuntimeError; end
    class HTTPException < RuntimeError; end
    class AuthError < RuntimeError; end
    class TargetError < RuntimeError
      attr_reader :info
      def initialize(error_info = {})
        @info = error_info
      end
    end
  end
end

# Utility accessors and methods for objects that want to access JSON web APIs.
module CF::UAA::Http

  attr_accessor :trace, :proxy, :async, :logger
  attr_reader :target

  private

  def json_get(url, authorization = nil)
    json_parse_reply(*http_get(url, 'application/json', authorization))
  end

  def json_parse(str)
    JSON.parse(str, :symbolize_names => true) if str
  end

  def json_parse_reply(status, body, headers)
    unless [200, 201, 400].include? status
      raise (status == 404 ? CF::UAA::NotFound : CF::UAA::BadResponse), "invalid status response from #{@target}: #{status}"
    end
    if headers && headers[:content_type] !~ /application\/json/i
      raise CF::UAA::BadResponse, "received invalid response content type from #{@target}"
    end
    parsed_reply = (JSON.parse(body, :symbolize_names => true) if body)
    if status == 400
      raise CF::UAA::TargetError.new(parsed_reply), "error response from #{@target}"
    end
    parsed_reply
  rescue JSON::ParserError
    raise CF::UAA::BadResponse, "invalid JSON response from #{@target}"
  end

  # HTTP helpers

  def http_get(path, content_type = nil, authorization = nil)
    headers = {}
    headers['Content-Type'] = content_type if content_type
    headers['Authorization'] = authorization if authorization
    request(:get, path, nil, headers)
  end

  def http_post(path, body, content_type, authorization)
    request(:post, path, body, 'Content-Type'=>content_type, 'Authorization'=>authorization)
  end

  def http_put(path, body, content_type, authorization)
    request(:put, path, body, 'Content-Type'=>content_type, 'Authorization'=>authorization)
  end

  def http_delete(path, authorization)
    request(:delete, path, nil, 'Authorization'=>authorization)[0]
  end

  def request(method, path, payload = nil, headers = {})
    headers = headers.dup
    headers['Proxy-User'] = @proxy if @proxy unless headers['Proxy-User']

    if headers['Content-Type']
      headers['Accept'] = headers['Content-Type'] unless headers['Accept']
    end

    raise CF::UAA::BadTarget, "Missing target. Target must be set before executing a request" unless @target

    req = {
      :method => method, :url => "#{@target}#{path}",
      :payload => payload, :headers => headers, :multipart => true
    }
    if trace
      debug_out "--->"
      debug_out "request: #{method} #{req[:url]}"
      debug_out "headers: #{headers}"
      debug_out "body: #{truncate(payload.to_s, 500)}" if payload
      debug_out "async: #{async.inspect}"
    end

    status, body, response_headers = async ? perform_ahttp_request(req) : perform_http_request(req)

    if trace
      debug_out "<---"
      debug_out "response: #{status}"
      debug_out "headers: #{response_headers}"
      debug_out "body: #{truncate(body.to_s, 500)}" if body
    end
    [status, body, response_headers]

  rescue Exception => e
    debug_out "<---- no response due to exception (#{e})" if trace
    raise
  end

  def perform_http_request(req)
    proxy_uri = URI.parse(req[:url]).find_proxy()
    RestClient.proxy = proxy_uri.to_s if proxy_uri

    result = nil
    RestClient::Request.execute(req) do |response, request|
      result = [ response.code, response.body, response.headers ]
    end
    result

  rescue URI::Error, SocketError, SystemCallError => e
    raise CF::UAA::BadTarget, "Cannot access target (#{e.message})"
  rescue RestClient::Exception, Net::HTTPBadResponse => e
    raise CF::UAA::HTTPException, "HTTP exception: #{e.class}: #{e}"
  end

  def perform_ahttp_request(req)
    f = Fiber.current
    connection = EventMachine::HttpRequest.new(req[:url], connect_timeout: 10, inactivity_timeout: 10)
    client = connection.setup_request(req[:method].to_sym, head: req[:headers], body: req[:payload])

    # This condition only works with em-http-request 1.0.0.beta.3
    if connection.is_a? EventMachine::FailedConnection
      raise CF::UAA::BadTarget, "HTTP connection setup error: #{client.error}"
    end

    client.callback {
      response_headers = client.response_header.inject({}) { |h, (k, v)| h[k.downcase.gsub('-', '_').to_sym] = v; h }
      f.resume [client.response_header.http_status, client.response, response_headers]
    }
    client.errback { f.resume [:error, client.error] }
    result = Fiber.yield
    if result[0] == :error
      raise CF::UAA::BadTarget, "connection failed" unless result[1] && result[1] != ""
      raise CF::UAA::HTTPException, result[1]
    end
    result
  end

  def truncate(str, limit = 30)
    stripped = str.strip[0..limit]
    stripped.length > limit ? stripped + '...': stripped
  end

  def debug_out(string)
    if logger
      logger.debug(string)
    else
      puts(string)
    end
  end

end
