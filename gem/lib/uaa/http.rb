require 'json/pure'
require 'open-uri'
require 'rest_client'

# Utility accessors and methods for objects that want to access JSON
# web APIs.
module Cloudfoundry::Uaa::Http

  class BadTarget < RuntimeError; end
  class AuthError < RuntimeError; end
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

  attr_accessor :trace, :proxy
  attr_reader :target

  private

  def json_get(url, authorization = nil)
    json_parse_reply(*http_get(url, 'application/json', authorization))
  end

  #def json_post(url, payload)
    #http_post(url, payload.to_json, 'application/json')
  #end

  #def json_put(url, payload)
    #http_put(url, payload.to_json, 'application/json')
  #end

  def json_parse(str)
    if str
      JSON.parse(str, :symbolize_names => true)
    end
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

  #def http_delete(path)
    #request(:delete, path)
  #end

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
    end
    status, body, response_headers = perform_http_request(req)

    # see comment on parse_error_message
    #if request_failed?(status)
      #err = (status == 404) ? NotFound : TargetError
      #raise err, parse_error_message(status, body)
    #else
      #return status, body, response_headers
    #end
  rescue URI::Error, SocketError, Errno::ECONNREFUSED => e
    raise BadTarget, "Cannot access target (%s)" % [ e.message ]
  end

  # see comment on parse_error_message
  #def request_failed?(status)
    #status >= 400
  #end

  def perform_http_request(req)
    proxy_uri = URI.parse(req[:url]).find_proxy()
    RestClient.proxy = proxy_uri.to_s if proxy_uri

    # Setup tracing if needed
    unless trace.nil?
      req[:headers]['X-VCAP-Trace'] = (trace == true ? '22' : trace)
    end

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

  def truncate(str, limit = 30)
    stripped = str.strip[0..limit]
    stripped.length > limit ? stripped + '...': stripped
  end

  # the uaa defines json error responses with fields other than 'code' and
  # 'description'. Error processing and json parsing has been commented
  # out of the http request/reponse level to allow the json level to
  # handle it without hiding other http errors.
  #def parse_error_message(status, body)
    #parsed_body = json_parse(body.to_s)
    #if parsed_body && parsed_body[:code] && parsed_body[:description]
      #desc = parsed_body[:description].gsub("\"","'")
      #"Error #{parsed_body[:code]}: #{desc}"
    #else
      #"Error (HTTP #{status}): #{body}"
    #end
  #rescue JSON::ParserError
    #if body.nil? || body.empty?
      #"Error (#{status}): No Response Received"
    #else
      #body_out = trace ? body : truncate(body)
      #"Error (JSON #{status}): #{body_out}"
    #end
  #end

end
