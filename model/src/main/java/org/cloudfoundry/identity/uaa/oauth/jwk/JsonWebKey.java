/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.jwk.JWKParameterNames;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.apache.commons.codec.binary.BaseNCodec.PEM_CHUNK_SIZE;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.oct;

/**
 * See https://tools.ietf.org/html/rfc7517
 */

@JsonDeserialize(using = JsonWebKeyDeserializer.class)
@JsonSerialize(using = JsonWebKeySerializer.class)
public class JsonWebKey {

    private static final Base64.Encoder base64encoder = Base64.getMimeEncoder(PEM_CHUNK_SIZE, "\n".getBytes(Charset.defaultCharset()));
    private static final Base64.Decoder base64decoder = Base64.getUrlDecoder();

    // value is not defined in RFC 7517
    public static final String PUBLIC_KEY_VALUE = "value";

    public enum KeyUse {
        sig,
        enc
    }

    // RFC 7518
    public enum KeyType {
        RSA,
        EC,
        MAC,
        oct
    }

    public enum KeyOperation {
        sign,
        verify,
        encrypt,
        decrypt,
        wrapKey,
        unwrapKey,
        deriveKey,
        deriveBits
    }

    private final Map<String, Object> json;

    public JsonWebKey(Map<String, Object> json) {
        if (json.get(JWKParameterNames.KEY_TYPE) == null) {
            throw new IllegalArgumentException("kty field is required");
        }
        KeyType.valueOf((String) json.get(JWKParameterNames.KEY_TYPE));
        this.json = new HashMap<>(json);
    }

    public Map<String, Object> getKeyProperties() {
        return Collections.unmodifiableMap(json);
    }

    public final KeyType getKty() {
        return KeyType.valueOf((String) getKeyProperties().get(JWKParameterNames.KEY_TYPE));
    }

    public final String getKid() {
        return (String) getKeyProperties().get(HeaderParameterNames.KEY_ID);
    }

    public JsonWebKey setKid(String kid) {
        this.json.put(HeaderParameterNames.KEY_ID, kid);
        return this;
    }

    public String[] getX5c() {
        return (String[]) getKeyProperties().get(HeaderParameterNames.X_509_CERT_CHAIN);
    }

    public JsonWebKey setX5c(String[] x5c) {
        this.json.put(HeaderParameterNames.X_509_CERT_CHAIN, x5c);
        return this;
    }

    public String getX5t() {
        return (String) getKeyProperties().get(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT);
    }

    public JsonWebKey setX5t(String x5t) {
        this.json.put(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT, x5t);
        return this;
    }

    public final KeyUse getUse() {
        String use = (String) getKeyProperties().get(JWKParameterNames.PUBLIC_KEY_USE);
        KeyUse result = null;
        if (UaaStringUtils.isNotEmpty(use)) {
            result = KeyUse.valueOf(use);
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof JsonWebKey)) {
            return false;
        }
        JsonWebKey that = (JsonWebKey) o;
        return getKid() != null ? (getKid().equals(that.getKid())) : (that.getKid() == null && getKeyProperties().equals(that.getKeyProperties()));
    }

    @Override
    public int hashCode() {
        if (getKid() == null) {
            return getKty().hashCode();
        } else {
            return getKid().hashCode();
        }
    }

    //helper methods
    public String getAlgorithm() {
        return (String) getKeyProperties().get(HeaderParameterNames.ALGORITHM);
    }

    public boolean hasValue() {
        return getKeyProperties().containsKey(PUBLIC_KEY_VALUE);
    }

    public String getValue() {
        String result = (String) getKeyProperties().get(PUBLIC_KEY_VALUE);
        if (result == null) {
            if (RSA == getKty()) {
                result = pemEncodePublicKey(getRsaPublicKey(this)).orElse(UaaStringUtils.EMPTY_STRING);
                this.json.put(PUBLIC_KEY_VALUE, result);
            } else if (MAC == getKty() || oct == getKty()) {
                result = (String) getKeyProperties().get(JWKParameterNames.OCT_KEY_VALUE);
                this.json.put(PUBLIC_KEY_VALUE, result);
            }
        }
        return result;
    }

    public Set<KeyOperation> getKeyOps() {
        List<String> result = (List<String>) getKeyProperties().get(JWKParameterNames.KEY_OPS);
        if (result == null) {
            result = Collections.emptyList();
        }
        return result.stream().map(KeyOperation::valueOf).collect(Collectors.toSet());
    }

    public static Optional<String> pemEncodePublicKey(PublicKey publicKey) {
        if (publicKey == null) {
            return Optional.empty();
        }
        String begin = "-----BEGIN PUBLIC KEY-----\n";
        String end = "\n-----END PUBLIC KEY-----";

        return Optional.of(begin + base64encoder.encodeToString(publicKey.getEncoded()) + end);
    }

    protected static PublicKey getRsaPublicKey(JsonWebKey key) {
        String e = (String) key.getKeyProperties().get(JWKParameterNames.RSA_EXPONENT);
        String n = (String) key.getKeyProperties().get(JWKParameterNames.RSA_MODULUS);

        if (e != null && n != null) {
            BigInteger modulus = new BigInteger(1, base64decoder.decode(n.getBytes(StandardCharsets.UTF_8)));
            BigInteger exponent = new BigInteger(1, base64decoder.decode(e.getBytes(StandardCharsets.UTF_8)));
            try {
                return KeyFactory.getInstance(RSA.name()).generatePublic(new RSAPublicKeySpec(modulus, exponent));
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e1) {
                throw new IllegalStateException(e1);
            }
        }
        return null;
    }
}
