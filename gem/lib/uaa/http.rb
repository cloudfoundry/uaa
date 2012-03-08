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
    if headers && headers[:content_type] !~ /application\/json/i
      raise BadTarget, "received invalid response content type from #{@target}"
    end
    if status != 200 && status != 400
      raise (status == 404 ? NotFound : BadResponse), "invalid status response from #{@target}: #{status}"
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

  #def http_delete(path)
    #request(:delete, path)
  #end

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
    unless logger.nil?
      debug_out "---"
      debug_out "method: #{method}"
      debug_out "url: #{req[:url]}"
      debug_out "payload: #{truncate(payload.to_s, 200)}" unless payload.nil?
      debug_out "headers: #{headers}"

    if trace
      puts "--->"
      puts "request: #{method} #{req[:url]}"
      puts "headers: #{headers}"
      puts "body: #{truncate(payload.to_s, 200)}" if payload
      puts "async: #{async.inspect}"
    end

    if async == true && EventMachine.reactor_running?
      status, body, response_headers = perform_ahttp_request(req)
    else
      status, body, response_headers = perform_http_request(req)
    end
    if trace
      puts "<---"
      puts "response: #{status}"
      puts "headers: #{response_headers}"
      puts "body: #{truncate(body.to_s, 200)}" if body
    end
    [status, body, response_headers]

  rescue URI::Error, SocketError => e
    raise BadTarget, "Cannot access target (#{e.message})"
  end

  def perform_http_request(req)
    proxy_uri = URI.parse(req[:url]).find_proxy()
    RestClient.proxy = proxy_uri.to_s if proxy_uri

    result = nil
    RestClient::Request.execute(req) do |response, request|
      result = [ response.code, response.body, response.headers ]
      unless trace.nil?
        debug_out '>>>'
        debug_out "ASYNC: FALSE"
        debug_out "PROXY: #{RestClient.proxy}" if RestClient.proxy
        debug_out "REQUEST: #{req[:method]} #{req[:url]}"
        debug_out "REQUEST_HEADERS:"
        req[:headers].each do |key, value|
            debug_out "    #{key} : #{value}"
        end
        debug_out "REQUEST_BODY: #{req[:payload]}" if req[:payload]
        debug_out "RESPONSE: [#{response.code}]"
        debug_out "RESPONSE_HEADERS:"
        response.headers.each do |key, value|
            debug_out "    #{key} : #{value}"
        end
        debug_out "BODY:"
        begin
            debug_out JSON.pretty_generate(JSON.parse(response.body))
        rescue
            debug_out "#{truncate(response.body, 200)}" if response.body
        end
        debug_out '<<<'
      end
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
      unless trace.nil?
        debug_out '>>>'
        debug_out "ASYNC: TRUE"
        debug_out "REQUEST: #{req[:method]} #{req[:url]}"
        debug_out "REQUEST_HEADERS:"
        req[:headers].each do |key, value|
            debug_out "    #{key} : #{value}"
        end
        debug_out "REQUEST_BODY: #{req[:payload]}" if req[:payload]
        debug_out "RESPONSE: [#{client.response_header.http_status}]"
        debug_out "RESPONSE_HEADERS:"
        response_headers.each do |key, value|
            debug_out "    #{key} : #{value}"
        end
        debug_out "BODY:"
        begin
            debug_out JSON.pretty_generate(JSON.parse(client.response))
        rescue
            debug_out "#{truncate(client.response, 200)}" if client.response
        end
        debug_out '<<<'
      end
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
