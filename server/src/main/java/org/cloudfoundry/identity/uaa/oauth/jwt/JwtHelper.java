/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.jwt.BinaryFormat;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.CharBuffer;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.security.jwt.codec.Codecs.b64UrlDecode;
import static org.springframework.security.jwt.codec.Codecs.b64UrlEncode;
import static org.springframework.security.jwt.codec.Codecs.concat;
import static org.springframework.security.jwt.codec.Codecs.utf8Decode;
import static org.springframework.security.jwt.codec.Codecs.utf8Encode;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JwtHelper {
    static byte[] PERIOD = utf8Encode(".");

    /**
     * Creates a token from an encoded token string.
     *
     * @param token the (non-null) encoded token (three Base-64 encoded strings separated
     *              by "." characters)
     */
    public static Jwt decode(String token) {
        int firstPeriod = token.indexOf('.');
        int lastPeriod = token.lastIndexOf('.');

        if (firstPeriod <= 0 || lastPeriod <= firstPeriod) {
            throw new IllegalArgumentException("JWT must have 3 tokens");
        }
        CharBuffer buffer = CharBuffer.wrap(token, 0, firstPeriod);
        // TODO: Use a Reader which supports CharBuffer
        JwtHeader header = JwtHeaderHelper.create(buffer.toString());

        buffer.limit(lastPeriod).position(firstPeriod + 1);
        byte[] claims = b64UrlDecode(buffer);
        boolean emptyCrypto = lastPeriod == token.length() - 1;

        byte[] crypto;

        if (emptyCrypto) {
            if (!"none".equals(header.parameters.alg)) {
                throw new IllegalArgumentException(
                  "Signed or encrypted token must have non-empty crypto segment");
            }
            crypto = new byte[0];
        } else {
            buffer.limit(token.length()).position(lastPeriod + 1);
            crypto = b64UrlDecode(buffer);
        }
        return new JwtImpl(header, claims, crypto);
    }

    public static Jwt decodeAndVerify(String token, SignatureVerifier verifier) {
        Jwt jwt = decode(token);
        jwt.verifySignature(verifier);

        return jwt;
    }

    public static Jwt encode(CharSequence content, Signer signer) {
        JwtHeader header = JwtHeaderHelper.create(signer);
        byte[] claims = utf8Encode(content);
        byte[] crypto = signer
          .sign(concat(b64UrlEncode(header.bytes()), PERIOD, b64UrlEncode(claims)));
        return new JwtImpl(header, claims, crypto);
    }
}

/**
 * Helper object for JwtHeader.
 * <p>
 * Handles the JSON parsing and serialization.
 */
class JwtHeaderHelper {
    static JwtHeader create(String header) {
        byte[] decodedBytes = b64UrlDecode(header);

        return new JwtHeader(decodedBytes, JsonUtils.readValue(decodedBytes, HeaderParameters.class));
    }

    static JwtHeader create(Signer signer) {
        HeaderParameters headerParameters =
          new HeaderParameters(signer.algorithm(), null, null, signer.keyId());

        return new JwtHeader(JsonUtils.writeValueAsBytes(headerParameters), headerParameters);
    }
}

/**
 * Header part of JWT
 */
class JwtHeader implements BinaryFormat {
    private final byte[] bytes;

    final HeaderParameters parameters;

    /**
     * @param bytes      the decoded header
     * @param parameters the parameter values contained in the header
     */
    JwtHeader(byte[] bytes, HeaderParameters parameters) {
        this.bytes = bytes;
        this.parameters = parameters;
    }

    @Override
    public byte[] bytes() {
        return bytes;
    }

    @Override
    public String toString() {
        return utf8Decode(bytes);
    }
}

class JwtImpl implements Jwt {
    private final JwtHeader header;

    private final byte[] content;

    private final byte[] crypto;

    private String claims;

    /**
     * @param header  the header, containing the JWS/JWE algorithm information.
     * @param content the base64-decoded "claims" segment (may be encrypted, depending on
     *                header information).
     * @param crypto  the base64-decoded "crypto" segment.
     */
    JwtImpl(JwtHeader header, byte[] content, byte[] crypto) {
        this.header = header;
        this.content = content;
        this.crypto = crypto;
        claims = utf8Decode(content);
    }

    /**
     * Validates a signature contained in the 'crypto' segment.
     *
     * @param verifier the signature verifier
     */
    @Override
    public void verifySignature(SignatureVerifier verifier) {
        verifier.verify(signingInput(), crypto);
    }

    private byte[] signingInput() {
        return concat(safeB64UrlEncode(header.bytes()), JwtHelper.PERIOD,
          safeB64UrlEncode(content));
    }

    private byte[] safeB64UrlEncode(byte[] bytes) {
        if (bytes.length == 0) {
            return bytes;
        } else {
            return b64UrlEncode(bytes);
        }
    }

    /**
     * Allows retrieval of the full token.
     *
     * @return the encoded header, claims and crypto segments concatenated with "."
     * characters
     */
    @Override
    public byte[] bytes() {
        return concat(b64UrlEncode(header.bytes()), JwtHelper.PERIOD,
          b64UrlEncode(content), JwtHelper.PERIOD, b64UrlEncode(crypto));
    }

    @Override
    public String getClaims() {
        return utf8Decode(content);
    }

    @Override
    public String getEncoded() {
        return utf8Decode(bytes());
    }

    @Override
    public String toString() {
        return header + " " + claims + " [" + crypto.length + " crypto bytes]";
    }

    @Override
    public HeaderParameters getHeader() {
        return header == null ? null : header.parameters;
    }
}
