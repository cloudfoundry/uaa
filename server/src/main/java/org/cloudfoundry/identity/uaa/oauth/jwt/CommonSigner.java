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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;

import java.text.ParseException;
import java.util.Optional;
import java.util.Set;

public class CommonSigner implements Signer {
    private final JWSSigner delegate;
    private final String algorithm;
    private final String keyId;
    private String keyURL;

    public CommonSigner(String keyId, String signingKey, String keyURL) {
        if (signingKey == null) {
            throw new IllegalArgumentException(signingKey);
        }
        KeyInfo keyInfo = new KeyInfo(keyId, signingKey, Optional.ofNullable(keyURL).orElse("http://localhost:8080/uaa"));
        this.delegate = keyInfo.getSigner();
        this.keyId = keyId;
        this.keyURL = keyURL;
        this.algorithm = keyInfo.algorithm();
    }


    private static boolean isAsymmetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }


    public String keyId() {
        return keyId;
    }


    public String keyURL() {
        return keyURL;
    }


    public byte[] sign(byte[] bytes) {
        return null;//delegate.sign(bytes);
    }

    public String algorithm() {
        return JwtAlgorithms.sigAlg(algorithm);
    }

    public String getJavaAlgorithm() {
        return algorithm;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        JWTClaimsSet claimsSet;
        try {
            claimsSet = JWTClaimsSet.parse(new String(signingInput));
            return new SignedJWT(header, claimsSet).getSignature();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return delegate.supportedJWSAlgorithms();
    }

    @Override
    public JCAContext getJCAContext() {
        return delegate.getJCAContext();
    }
}
