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
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.util.Set;

public class CommonSignatureVerifier implements JWSVerifier {
    private final JWSVerifier delegate;

    public CommonSignatureVerifier(String verificationKey) {
        if(verificationKey == null) {
            throw new IllegalArgumentException("verificationKey cannot be null");
        } else if(isAssymetricKey(verificationKey)) {
            try {
                delegate = new RSASSAVerifier(JWK.parseFromPEMEncodedObjects(verificationKey).toRSAKey().toRSAPublicKey());
            } catch (JOSEException e) {
                throw new InvalidTokenException("Verify failed", e);
            }
        } else {
            try {
                delegate = new MACVerifier(verificationKey);
            } catch (JOSEException e) {
                throw new InvalidTokenException("Verify failed", e);
            }
        }
    }

    private static boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }


    public void verify(byte[] content, byte[] signature) {

    }


    public String algorithm() {
        return "";
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
        return delegate.verify(header, signingInput, signature);
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
