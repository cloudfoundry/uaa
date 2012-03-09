#
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
#

require 'json/pure'
require 'open-uri'
require 'rest_client'
require 'eventmachine'
require 'em-http'
require 'fiber'

module Cloudfoundry; module Uaa; end; end

# Utility accessors and methods for objects that want to access JSON
# web APIs.
module Cloudfoundry::Uaa::Http

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
      raise (status == 404 ? NotFound : BadResponse), "invalid status response from #{@target}: #{status}"
    end
    if headers && headers[:content_type] !~ /application\/json/i
      raise BadTarget, "received invalid response content type from #{@target}"
    end
    parsed_reply = (JSON.parse(body, :symbolize_names => true) if body)
    if status == 400
      raise TargetError.new(parsed_reply), "error response from #{@target}"
    end
    parsed_reply
  rescue JSON::ParserError
    raise BadResponse, "invalid JSON response from #{@target}"
  end

  # HTTP helpers

  def http_get(path, content_type=nil, authorization=nil)
    headers = {'Content-Type' => content_type}
    headers['Authorization'] = authorization if authorization
    request(:get, path, nil, headers)
  end

  def http_post(path, body, content_type=nil, authorization=nil)
    request(:post, path, body, 'Content-Type'=>content_type, 'Authorization'=>authorization)
  end

  def http_put(path, body, content_type=nil, authorization=nil)
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

    raise BadTarget, "Missing target. Please set the target before executing a request" unless @target

    req = {
      :method => method, :url => "#{@target}#{path}",
      :payload => payload, :headers => headers, :multipart => true
    }
    if trace
      debug_out "--->"
      debug_out "request: #{method} #{req[:url]}"
      debug_out "headers: #{headers}"
      debug_out "body: #{truncate(payload.to_s, 200)}" if payload
      debug_out "async: #{async.inspect}"
    end

    if async == true && EventMachine.reactor_running?
      status, body, response_headers = perform_ahttp_request(req)
    else
      status, body, response_headers = perform_http_request(req)
    end

    if trace
      debug_out "<---"
      debug_out "response: #{status}"
      debug_out "headers: #{response_headers}"
      debug_out "body: #{truncate(body.to_s, 200)}" if body
    end
    [status, body, response_headers]

  rescue URI::Error, SocketError => e
    debug_out "<---- no response due to exception (#{e})" if trace
    raise BadTarget, "Cannot access target (#{e.message})"
  rescue e
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

  rescue Net::HTTPBadResponse => e
    raise BadTarget, "Received bad HTTP response from target: #{e}"
  rescue SystemCallError, RestClient::Exception => e
    raise HTTPException, "HTTP exception: #{e.class}:#{e}"
  end

  def perform_ahttp_request(req)
    url = req[:url]
    method = req[:method]
    headers = req[:headers]
    payload = req[:payload]

    f = Fiber.current
    opts ={:connect_timeout => 10, :inactivity_timeout => 10}
    connection = EventMachine::HttpRequest.new(url, opts)
    client = connection.setup_request(method.to_sym, :head => headers, :body => payload)
    client.callback {
      response_headers = client.response_header.inject({}) { |h, (k, v)| h[k.downcase.to_sym] = v; h }
      f.resume [client.response_header.http_status, client.response, response_headers]
    }
    client.errback  { f.resume HTTPException.new("An error occurred in the HTTP request: #{http.errors}", self) }

    return Fiber.yield
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
