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
require "uaa/util"

module CF::UAA

class DecodeError < RuntimeError; end

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
class TokenCoder

  def self.init_digest(algo)
    OpenSSL::Digest::Digest.new(algo.sub('HS', 'sha').sub('RS', 'sha'))
  end

  def self.base64url_decode(str)
    return nil unless str
    str += '=' * (4 - str.length.modulo(4))
    Base64.decode64(str.gsub("-", "+").gsub("_", "/"))
  end

  def self.base64url_encode(str)
    return nil unless str
    Base64.encode64(str).gsub("+", "-").gsub("/", "_").gsub("\n", "").gsub('=', '')
  end

  # takes a token_body (the middle section of the jwt) and returns a signed token
  def self.encode(token_body, skey, pkey = nil, algo = 'HS256')
    segments = [base64url_encode({"typ" => "JWT", "alg" => algo}.to_json)]
    segments << base64url_encode(token_body.to_json)
    if ["HS256", "HS384", "HS512"].include?(algo)
      sig = OpenSSL::HMAC.digest(init_digest(algo), skey, segments.join('.'))
    elsif ["RS256", "RS384", "RS512"].include?(algo)
      sig = pkey.sign(init_digest(algo), segments.join('.'))
    elsif algo == "none"
      sig = ""
    else
      raise ArgumentError, "unsupported signing method"
    end
    segments << base64url_encode(sig)
    segments.join('.')
  end

  def self.decode(token, skey, pkey = nil, verify = true)
    segments = token.split('.')
    raise DecodeError, "Not enough or too many segments" unless [2,3].include? segments.length
    header_segment, payload_segment, crypto_segment = segments
    signing_input = [header_segment, payload_segment].join('.')
    begin
      header = JSON.parse(base64url_decode(header_segment))
      payload = JSON.parse(base64url_decode(payload_segment), symbolize_names: true)
      signature = base64url_decode(crypto_segment) if verify
    rescue JSON::ParserError
      raise DecodeError, "Invalid segment encoding"
    end
    return payload if !verify || (algo = header['alg']) == "none"
    if ["HS256", "HS384", "HS512"].include?(algo)
      raise DecodeError, "Signature verification failed" unless
          signature == OpenSSL::HMAC.digest(init_digest(algo), skey, signing_input)
    elsif ["RS256", "RS384", "RS512"].include?(algo)
      raise DecodeError, "Signature verification failed" unless
          pkey.verify(init_digest(algo), signature, signing_input)
    else
      raise DecodeError, "Algorithm not supported"
    end
    payload
  end

  # Create a new token en/decoder for a service that is associated with
  # the the audience_ids, the symmetrical token validation key, and the
  # public and/or private keys. pkey may be a string or File which includes
  # public and/or private key data in PEM or DER formats.
  # The audience_ids may be an array or space separated strings and should
  # indicate values which indicate the token is intended for this service
  # instance. It will be compared with tokens as they are decoded to
  # ensure that the token was intended for this resource. The skey
  # is used by the token granter (Authorization Server) to sign
  # the token using symetrical key algoruthms, while the public key
  # is used to validate signatures for public/private key algorithms.
  def initialize(audience_ids, skey, pkey)
    @audience_ids, @skey, @pkey = Util.normalize_scope(audience_ids), skey, pkey
    @pkey = OpenSSL::PKey::RSA.new(pkey) unless pkey.nil? || pkey.is_a?(OpenSSL::PKey::PKey)
  end

  # Encode a JWT token. Takes a hash of values to use as the token body.
  # Returns a signed token in JWT format (header, body, signature).
  # Algorithm may be HS256, HS384, HS512, RS256, RS384, RS512, or none --
  # assuming the TokenCoder instance is configured with the appropriate
  # key -- i.e. pkey must include a private key for the RS algorithms.
  def encode(token_body = {}, algorithm = 'HS256')
    unless token_body[:aud] || token_body["aud"]
      token_body[:aud] = @audience_ids
    end
    unless token_body[:exp] || token_body["exp"]
      token_body[:exp] = Time.now.to_i + 7 * 24 * 60 * 60
    end
    self.class.encode(token_body, @skey, @pkey, algorithm)
  end

  # Returns hash of values decoded from the token contents. If the
  # token contains resource ids and they do not contain the id of the
  # caller there will be an AuthError. If the token has expired there
  # will also be an AuthError.
  def decode(auth_header)
    unless auth_header && (tkn = auth_header.split).length == 2 && tkn[0] =~ /^bearer$/i
      raise DecodeError, "invalid authentication header: #{auth_header}"
    end
    reply = self.class.decode(tkn[1], @skey, @pkey)
    auds = Util.normalize_scope(reply[:aud])
    if auds && @audience_ids && (auds & @audience_ids).empty?
      raise AuthError, "invalid audience: #{reply[:aud]}"
    end
    unless reply[:exp].is_a?(Integer) && reply[:exp] > Time.now.to_i
      raise AuthError, "token expired"
    end
    reply
  end

end

end
