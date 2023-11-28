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
package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeyHelper;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class CommonSignatureVerifier {
    private final JsonWebKey delegate;
    private final String algorithm;
    private JWKSet jwk;

    public CommonSignatureVerifier(String keyId, String alg, JWK verificationKey) {
        if (keyId == null || alg == null) {
            this.jwk = new JWKSet(verificationKey);
            this.delegate = JsonWebKeyHelper.parseConfiguration(verificationKey.toJSONString()).getKeys().get(0);
            this.algorithm = this.delegate.getAlgorithm();
        } else {
            this.algorithm = alg;
            Map<String, Object> keyMap = verificationKey.toJSONObject();
            keyMap.put(HeaderParameterNames.KEY_ID, keyId);
            keyMap.put(HeaderParameterNames.ALGORITHM, alg);
            try {
                this.jwk = new JWKSet(JWK.parse(keyMap));
                this.delegate = JsonWebKeyHelper.parseConfiguration(jwk.getKeyByKeyId(keyId).toJSONString()).getKeys().get(0);
            } catch (ParseException e) {
                throw new IllegalArgumentException(e);
            }
        }
    }

    public CommonSignatureVerifier(JsonWebKey verificationKey) {
        if(verificationKey == null) {
            throw new IllegalArgumentException("verificationKey cannot be null");
        } else if(verificationKey.getKty() == JsonWebKey.KeyType.RSA) {
            try {
                RSAKey rsaKey = verificationKey.getValue() != null ? JsonWebKeyHelper.getJsonWebKey(verificationKey.getValue()).toRSAKey() : RSAKey.parse(verificationKey.getKeyProperties());
                algorithm = Optional.ofNullable(verificationKey.getAlgorithm()).orElse(JWSAlgorithm.RS256.getName());
                delegate = verificationKey;//new RsaVerifier(rsaKey.toRSAPublicKey(), JwtAlgorithms.sigAlgJava(jwtAlg));
            } catch (ParseException | JOSEException e) {
                throw new IllegalArgumentException(e);
            }
        } else if(verificationKey.getKty() == JsonWebKey.KeyType.EC) {
            try {
                ECKey ecKey = ECKey.parse(verificationKey.getKeyProperties());
                algorithm = Optional.ofNullable(verificationKey.getAlgorithm()).orElse(JWSAlgorithm.ES256.getName());
                delegate = verificationKey;//new EllipticCurveVerifier(ecKey.toECPublicKey(), JwtAlgorithms.sigAlgJava(jwtAlg));
            } catch (ParseException  e) {
                throw new IllegalArgumentException(e);
            }
        } else {
            algorithm = Optional.ofNullable(verificationKey.getAlgorithm()).orElse(JWSAlgorithm.HS256.getName());
            delegate = verificationKey;//new MacSigner(JwtAlgorithms.sigAlgJava(jwtAlg), new SecretKeySpec(verificationKey.getValue().getBytes(), jwtAlg));
        }
    }

    public String algorithm() {
        return algorithm;
    }

    public JWKSet getJwkSet() {
        return this.jwk;
    }

    public JWKSet getJwkSet(String keyId) {
        try {
            Map<String, Object> keyMap = new HashMap<>(delegate.getKeyProperties());
            keyMap.put(HeaderParameterNames.KEY_ID, keyId);
            return new JWKSet(JWK.parse(keyMap));
        } catch (ParseException e) {
            // ignore
        }
        return new JWKSet();
    }
}
