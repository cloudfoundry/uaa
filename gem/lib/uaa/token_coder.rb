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

require "base64"
require "openssl"
require "json/pure"

module CF
  module UAA
    class DecodeError < RuntimeError; end
    class AuthError < RuntimeError; end
  end
end

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
class CF::UAA::TokenCoder

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

  # takes a token_body (the middle section of the jwt) and returns a signed access_token
  def self.encode(token_body, signing_secret)
    algorithm = 'HS256'
    segments = [base64url_encode({"typ" => "JWT", "alg" => algorithm}.to_json)]
    segments << base64url_encode(token_body.to_json)
    segments << base64url_encode(sign(algorithm, segments.join('.'), signing_secret))
    segments.join('.')
  end

  def self.decode(token, signing_secret)
    segments = token.split('.')
    unless (segments.length == 2 || segments.length == 3)
      raise CF::UAA::DecodeError, "Not enough or too many segments"
    end
    header_segment, payload_segment, crypto_segment = segments
    signing_input = [header_segment, payload_segment].join('.')
    begin
      header = JSON.parse(base64url_decode(header_segment))
      payload = JSON.parse(base64url_decode(payload_segment), :symbolize_names => true)
      signature = base64url_decode(crypto_segment)
    rescue JSON::ParserError
      raise CF::UAA::DecodeError, "Invalid segment encoding"
    end
    algo = header['alg']
    unless ["HS256", "HS384", "HS512"].include?(algo)
      raise CF::UAA::DecodeError, "Algorithm not supported"
    end
    unless signature == sign(algo, [header_segment, payload_segment].join('.'), signing_secret)
      raise CF::UAA::AuthError, "Signature verification failed"
    end
    payload
  end

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

  # Encode a JWT token. Takes a hash of values to use as the token body.
  # Returns a signed token in JWT format (header, body, signature).
  def encode(token_body = {})
    unless token_body[:resource_ids] || token_body["resource_ids"]
      token_body[:resource_ids] = [@resource_id]
    end
    unless token_body[:expires_at] || token_body["expires_at"]
      token_body[:expires_at] = Time.now.to_i + 7 * 24 * 60 * 60
    end
    self.class.encode(token_body, @secret)
  end

  # Returns hash of values decoded from the token contents. If the
  # token contains resource ids and they do not contain the id of the
  # caller there will be an AuthError. If the token has expired there
  # will also be an AuthError.
  def decode(auth_header)
    unless auth_header && (tkn = auth_header.split).length == 2 && tkn[0] =~ /bearer/i
      raise CF::UAA::DecodeError, "invalid authentication header: #{auth_header}"
    end
    reply = self.class.decode(tkn[1], @secret)
    unless reply[:resource_ids] && reply[:resource_ids].include?(@resource_id)
      raise CF::UAA::AuthError, "invalid resource audience: #{reply[:resource_ids]}"
    end
    unless reply[:expires_at].is_a?(Integer) && reply[:expires_at] > Time.now.to_i
      raise CF::UAA::AuthError, "token expired"
    end
    reply
  end

end
