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

# this is starting to look like some utility classes and methods
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

    # http headers and various protocol tags tend to contain '-' characters
    # and are intended to be case-insensitive -- and often end up as keys in ruby
    # hashes. This code converts these keys to symbols, downcased for at least
    # consistent case if not exactly case insensitive, and with '_' instead
    # of '-' for ruby convention.
    def self.rubyize_keys(obj)
      return obj.collect {|o| rubyize_keys(o)} if obj.is_a? Array
      return obj unless obj.is_a? Hash
      obj.each_with_object({}) {|(k, v), h| h[k.to_s.downcase.gsub('-', '_').to_sym] = rubyize_keys(v) }
    end

    # opposite of the above: converts keys from symbols with '_' to strings with '-'
    def self.unrubyize_keys(obj)
      return obj.collect {|o| unrubyize_keys(o)} if obj.is_a? Array
      return obj unless obj.is_a? Hash
      obj.each_with_object({}) {|(k, v), h| h[k.to_s.gsub('_', '-')] = unrubyize_keys(v) }
    end

    def self.json_parse(str)
      rubyize_keys(JSON.parse(str)) if str
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

  def json_parse_reply(status, body, headers)
    unless [200, 201, 400, 401, 403].include? status
      raise (status == 404 ? CF::UAA::NotFound : CF::UAA::BadResponse), "invalid status response from #{@target}: #{status}"
    end
    if headers && headers[:content_type] !~ /application\/json/i
      raise CF::UAA::BadResponse, "received invalid response content type from #{@target}"
    end
    parsed_reply = CF::UAA.json_parse(body)
    if status == 400 || status == 401 || status == 403
      raise CF::UAA::TargetError.new(parsed_reply), "error response from #{@target}"
    end
    parsed_reply
  rescue JSON::ParserError
    raise CF::UAA::BadResponse, "invalid JSON response from #{@target}"
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

    if headers[:content_type]
      headers[:accept] = headers[:content_type] unless headers[:accept]
    end

    raise CF::UAA::BadTarget, "Missing target. Target must be set before executing a request" unless @target

    req = { method: method, url: "#{@target}#{path}", payload: payload,
        headers: CF::UAA.unrubyize_keys(headers), :multipart => true }
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
      debug_out "headers: #{CF::UAA.rubyize_keys(response_headers)}"
      debug_out "body: #{truncate(body.to_s, 500)}" if body
    end
    [status, body, CF::UAA.rubyize_keys(response_headers)]

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
    raise CF::UAA::BadTarget, "HTTP connection setup error: #{client.error}" if connection.is_a? EventMachine::FailedConnection

    client.callback { f.resume [client.response_header.http_status, client.response, client.response_header] }
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
    logger ? logger.debug(string) : puts(string)
  end

end
