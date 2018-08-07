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
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;
import static org.springframework.util.StringUtils.hasText;

/**
 * See https://tools.ietf.org/html/rfc7517
 */

@JsonDeserialize(using = JsonWebKeyDeserializer.class)
@JsonSerialize(using = JsonWebKeySerializer.class)
public class JsonWebKey {


    public enum KeyUse {
        sig,
        enc
    }

    public enum KeyType {
        RSA,
        MAC
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

    public static String KID = "kid";
    public static String KTY = "kty";
    public static String ALG = "alg";

    private final Map<String, Object> json;

    public JsonWebKey(Map<String, Object> json) {
        if (json.get("kty") == null) {
            throw new IllegalArgumentException("kty field is required");
        }
        KeyType.valueOf((String) json.get("kty"));
        this.json = new HashMap(json);
    }

    public Map<String, Object> getKeyProperties() {
        return Collections.unmodifiableMap(json);
    }

    public final KeyType getKty() {
        return KeyType.valueOf((String) getKeyProperties().get(KTY));
    }

    public final String getKid() {
        return (String) getKeyProperties().get(KID);
    }

    public JsonWebKey setKid(String kid) {
        this.json.put(KID, kid);
        return this;
    }

    public final KeyUse getUse() {
        String use = (String) getKeyProperties().get("use");
        KeyUse result = null;
        if (hasText(use)) {
            result = KeyUse.valueOf(use);
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JsonWebKey)) return false;
        JsonWebKey that = (JsonWebKey) o;
        return getKid() != null ? getKid().equals(that.getKid()) : that.getKid() == null && getKeyProperties().equals(that.getKeyProperties());
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
        return (String) getKeyProperties().get(ALG);
    }

    public String getValue() {
        String result = (String) getKeyProperties().get("value");
        if (result == null) {
            if (RSA.equals(getKty())) {
                result = pemEncodePublicKey(getRsaPublicKey(this));
                this.json.put("value", result);
            } else if (MAC.equals(getKty())) {
                result = (String) getKeyProperties().get("k");
                this.json.put("value", result);
            }
        }
        return result;
    }

    public Set<KeyOperation> getKeyOps() {
        List<String> result = (List<String>) getKeyProperties().get("key_ops");
        if (result==null) {
            result = Collections.emptyList();
        }
        return result.stream().map(o -> KeyOperation.valueOf(o)).collect(Collectors.toSet());
    }

    public static String pemEncodePublicKey(PublicKey publicKey) {
        String begin = "-----BEGIN PUBLIC KEY-----\n";
        String end = "\n-----END PUBLIC KEY-----";
        byte[] data = publicKey.getEncoded();
        String base64encoded = new String(new Base64(false).encode(data));
        return begin + base64encoded + end;
    }

    public static PublicKey getRsaPublicKey(JsonWebKey key) {
        final Base64 decoder = new Base64(true);
        String e = (String) key.getKeyProperties().get("e");
        String n = (String) key.getKeyProperties().get("n");
        BigInteger modulus = new BigInteger(1, decoder.decode(n.getBytes(StandardCharsets.UTF_8)));
        BigInteger exponent = new BigInteger(1, decoder.decode(e.getBytes(StandardCharsets.UTF_8)));
        try {
            return KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(modulus, exponent)
            );
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e1) {
            throw new IllegalStateException(e1);
        }
    }
}
