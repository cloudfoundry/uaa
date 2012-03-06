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
  class TargetError < RuntimeError; end
  class NotFound < RuntimeError; end
  class BadResponse < RuntimeError; end
  class HTTPException < RuntimeError; end
  class TargetJsonError < TargetError
    attr_reader :info
    def initialize(parsed_error_info)
      @info = parsed_error_info
    end
  end

  attr_accessor :trace, :proxy, :async
  attr_reader :target

  private

  def json_get(url, authorization = nil)
    json_parse_reply(*http_get(url, 'application/json', authorization))
  end

  def json_parse(str)
    str ? JSON.parse(str, :symbolize_names => true) : nil
  end

  def json_parse_reply(status, body, headers)
    if headers && headers[:content_type] !~ /application\/json/i
      raise BadTarget, "received invalid response content type from #{@target}"
    end
    if status != 200 && status != 400
      raise (status == 404 ? NotFound : BadResponse), "invalid status response from #{@target}: #{status}"
    end
    parsed_reply = body ? JSON.parse(body, :symbolize_names => true): nil
    if status == 400
      raise TargetJsonError.new(parsed_reply), "error response from #{@target}"
    end
    parsed_reply
  rescue JSON::ParserError
    raise BadResponse, "invalid JSON response from #{@target}"
  end

  # HTTP helpers

  def http_get(path, content_type=nil, authorization=nil)
    request(:get, path, nil, 'Content-Type'=>content_type, 'Authorization'=>authorization)
  end

  def http_post(path, body, content_type=nil, authorization=nil)
    request(:post, path, body, 'Content-Type'=>content_type, 'Authorization'=>authorization)
  end

  def http_put(path, body, content_type=nil, authorization=nil)
    request(:put, path, body, 'Content-Type'=>content_type, 'Authorization'=>authorization)
  end

  def http_delete(path)
    request(:delete, path)
  end

  def request(method, path, payload = nil, headers = {})
    headers = headers.dup
    headers['Proxy-User'] = @proxy if @proxy unless headers['Proxy-User']

    if headers['Content-Type']
      headers['Accept'] = headers['Content-Type'] unless headers['Accept']
    end

    raise BadTarget, "Missing target. Please set the target attribute before executing a request" if !@target

    req = {
      :method => method, :url => "#{@target}#{path}",
      :payload => payload, :headers => headers, :multipart => true
    }
    unless trace.nil?
      puts "---"
      puts "method: #{method}"
      puts "url: #{req[:url]}"
      puts "payload: #{truncate(payload.to_s, 200)}" unless payload.nil?
      puts "headers: #{headers}"
      puts "async: #{async.inspect}"

      # Setup tracing if needed
      req[:headers]['X-VCAP-Trace'] = (trace == true ? '22' : trace)
    end
    if async == true && EventMachine.reactor_running?
      status, body, response_headers = perform_ahttp_request(req)
    else
      status, body, response_headers = perform_http_request(req)
    end
  rescue URI::Error, SocketError, Errno::ECONNREFUSED => e
    raise BadTarget, "Cannot access target (%s)" % [ e.message ]
  end

  def perform_http_request(req)
    proxy_uri = URI.parse(req[:url]).find_proxy()
    RestClient.proxy = proxy_uri.to_s if proxy_uri

    result = nil
    RestClient::Request.execute(req) do |response, request|
      result = [ response.code, response.body, response.headers ]
      unless trace.nil?
        puts '>>>'
        puts "PROXY: #{RestClient.proxy}" if RestClient.proxy
        puts "REQUEST: #{req[:method]} #{req[:url]}"
        puts "REQUEST_HEADERS:"
        req[:headers].each do |key, value|
            puts "    #{key} : #{value}"
        end
        puts "REQUEST_BODY: #{req[:payload]}" if req[:payload]
        puts "RESPONSE: [#{response.code}]"
        puts "RESPONSE_HEADERS:"
        response.headers.each do |key, value|
            puts "    #{key} : #{value}"
        end
        begin
            puts JSON.pretty_generate(JSON.parse(response.body))
        rescue
            puts "#{truncate(response.body, 200)}" if response.body
        end
        puts '<<<'
      end
    end
    result
  rescue Net::HTTPBadResponse => e
    raise BadTarget "Received bad HTTP response from target: #{e}"
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
      unless trace.nil?
        puts '>>>'
        puts "REQUEST: #{req[:method]} #{req[:url]}"
        puts "REQUEST_HEADERS:"
        req[:headers].each do |key, value|
            puts "    #{key} : #{value}"
        end
        puts "REQUEST_BODY: #{req[:payload]}" if req[:payload]
        puts "RESPONSE: [#{client.response.http_status}]"
        puts "RESPONSE_HEADERS:"
        client.response_header.each do |key, value|
            puts "    #{key} : #{value}"
        end
        begin
            puts JSON.pretty_generate(JSON.parse(client.response))
        rescue
            puts "#{truncate(client.response, 200)}" if client.response
        end
        puts '<<<'
      end
      f.resume [client.response_header.http_status, client.response, client.response_header]
    }
    client.errback  { f.resume HTTPException.new("An error occurred in the HTTP request: #{http.errors}", self) }

    return Fiber.yield
  end

  def truncate(str, limit = 30)
    stripped = str.strip[0..limit]
    stripped.length > limit ? stripped + '...': stripped
  end

end
