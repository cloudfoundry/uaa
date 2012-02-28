# This class is for resource servers

# Resource servers get tokens and need to validate and decode them, but they
# do not initiate their creation with the AS. This class it for resource
# servers which only accept Bearer JWT tokens and has the secret that can be
# used to verify the signature of the token.

require "base64"
require "openssl"
require "json/pure"

module Cloudfoundry; module Uaa; end; end

class Cloudfoundry::Uaa::TokenCoder

  class DecodeError < RuntimeError; end
  class AuthError < RuntimeError; end

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

  def initialize(resource_id, signing_secret)
    @resource_id, @secret = resource_id, signing_secret
  end

  def encode(token_body = {})
    unless token_body[:resource_ids] || token_body["resource_ids"]
      token_body[:resource_ids] = [@resource_id]
    end
    unless token_body[:expires_at] || token_body["expires_at"]
      token_body[:expires_at] = Time.now.to_i + 7 * 24 * 60 * 60
    end
    self.class.encode(token_body, @secret)
  end

  # returns hash of values decoded from the token contents
  def decode(auth_header)
    unless auth_header && (tkn = auth_header.split).length == 2 && tkn[0] =~ /bearer/i
      raise DecodeError, "invalid authentication header: #{auth_header}"
    end
    reply = self.class.decode(tkn[1], @secret)
    unless reply[:resource_ids] && reply[:resource_ids].include?(@resource_id)
      raise AuthError, "invalid resource audience: #{reply[:resource_ids]}"
    end
    unless reply[:expires_at].is_a?(Integer) && reply[:expires_at] > Time.now.to_i
      raise AuthError, "token expired"
    end
    reply
  end

end
