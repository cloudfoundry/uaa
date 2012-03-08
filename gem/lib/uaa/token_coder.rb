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

require "base64"
require "openssl"
require "json/pure"

module Cloudfoundry; module Uaa; end; end

# This class is for OAuth Resource Servers.

# Resource Servers get tokens and need to validate and decode them,
# but they do not obtain them from the Authorization Server. This
# class it for Resource Servers which accept Bearer JWT tokens.  An
# instance of this class can be used to decode and verify the contents
# of a bearer token.  The Authorization Server will have signed the
# token and shared a secret key so that the Resource Server can verify
# the signature.  The Authorization Server may also have given the
# Resource Server an id, in which case it must verify a matching value
# is in the access token.
class Cloudfoundry::Uaa::TokenCoder

  class DecodeError < RuntimeError; end
  class AuthError < RuntimeError; end

  # Create a new token coder for the resource id and signing secret
  # provided. The resource id expresses the audience of an access
  # token and will be compared with tokens as they are decoded to
  # ensure that the token was intenbded for this resource. The signing
  # secret is used by the token granter (Authorization Server) to sign
  # the key so that we can verify its source. The Authorization Server
  # shares this secret with its trusted Resource Servers.
  def initialize(resource_id, signing_secret)
    @resource_id, @secret = resource_id, signing_secret
  end

  # Encode an access token provided as a hash. The hash should contain
  # the token value, plus optionally expiry and target resource ids,
  # e.g.
  #
  #   { 
  #     :access_token => "HGKHDFKDSHJF", 
  #     :expires_at => 13455876,
  #     :resource_ids => ["cloud_controller", "other"]
  #   }
  #
  # The expires_at field is in seconds since epoch.
  def encode(access_token = {})
    unless access_token[:resource_ids] || access_token["resource_ids"]
      access_token[:resource_ids] = [@resource_id]
    end
    unless access_token[:expires_at] || access_token["expires_at"]
      access_token[:expires_at] = Time.now.to_i + 7 * 24 * 60 * 60
    end
    self.class.encode(access_token, @secret)
  end

  # Returns hash of values decoded from the token contents. If the
  # token contains resource ids and they do not contain the id of the
  # caller there will be an AuthError. If the token has expired there
  # will also be an AuthError.
  def decode(auth_header)
    unless auth_header && (token = auth_header.split).length == 2 && token[0] =~ /bearer/i
      raise DecodeError, "invalid authentication header: #{auth_header}"
    end
    reply = self.class.decode(token[1], @secret)
    unless reply[:resource_ids] && reply[:resource_ids].include?(@resource_id)
      raise AuthError, "invalid resource audience: #{reply[:resource_ids]}"
    end
    unless reply[:expires_at].is_a?(Integer) && reply[:expires_at] > Time.now.to_i
      raise AuthError, "token expired"
    end
    reply
  end

  private

  def self.sign(algorithm, msg, signing_secret)
    raise DecodeError, "unsupported signing method" unless ["HS256", "HS384", "HS512"].include?(algorithm)
    OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new(algorithm.sub('HS', 'sha')), signing_secret, msg)
  end

  def self.base64url_decode(str)
    str += '=' * (4 - str.length.modulo(4))
    Base64.decode64(str.gsub("-", "+").gsub("_", "/"))
  end

  def self.base64url_encode(str)
    Base64.encode64(str).gsub("+", "-").gsub("/", "_").gsub("\n", "").gsub('=', '')
  end

  def self.encode(access_token, signing_secret)
    algorithm = 'HS256'
    segments = [base64url_encode({"typ" => "JWT", "alg" => algorithm}.to_json)]
    segments << base64url_encode(access_token.to_json)
    segments << base64url_encode(sign(algorithm, segments.join('.'), signing_secret))
    segments.join('.')
  end

  def self.decode(token, signing_secret)
    segments = token.split('.')
    unless (segments.length == 2 || segments.length == 3)
      raise DecodeError, "Not enough or too many segments"
    end
    header_segment, payload_segment, crypto_segment = segments
    signing_input = [header_segment, payload_segment].join('.')
    begin
      header = JSON.parse(base64url_decode(header_segment))
      payload = JSON.parse(base64url_decode(payload_segment), :symbolize_names => true)
      signature = base64url_decode(crypto_segment)
    rescue JSON::ParserError
      raise DecodeError, "Invalid segment encoding"
    end
    algo = header['alg']
    unless ["HS256", "HS384", "HS512"].include?(algo)
      raise DecodeError, "Algorithm not supported"
    end
    unless signature == sign(algo, [header_segment, payload_segment].join('.'), signing_secret)
      raise AuthError, "Signature verification failed"
    end
    payload
  end

end
