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

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyUse.sig;


public class RsaJsonWebKey extends JsonWebKey {

    private static Base64 base64 = new Base64(true);

    public static RsaJsonWebKey fromPEMPrivateKey(String key) {
        KeyPair pair = KeyInfo.parseKeyPair(key);
        RSAPublicKey rsaKey = (RSAPublicKey) pair.getPublic();
        BigInteger modulus = rsaKey.getModulus();
        BigInteger exponent = rsaKey.getPublicExponent();
        Map<String, Object> properties = new HashMap();
        properties.put("n", base64.encodeAsString(modulus.toByteArray()));
        properties.put("e", base64.encodeAsString(exponent.toByteArray()));
        properties.put("kty", "RSA");
        properties.put("use", sig.name());
        return new RsaJsonWebKey(properties);
    }

    public static RsaJsonWebKey fromPEMPublicKey(String key) {
        return null;
    }

    public RsaJsonWebKey(Map<String, Object> json) {
        super(json);
    }

    @Override
    public PublicKey getPublicKey() {
        final Base64 decoder = new Base64(true);
        String e = (String) getKeyProperties().get("e");
        String n = (String) getKeyProperties().get("n");
        BigInteger modulus  = new BigInteger(1, decoder.decode(n.getBytes(StandardCharsets.UTF_8)));
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
