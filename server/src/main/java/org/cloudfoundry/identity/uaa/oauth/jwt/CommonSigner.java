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
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;

public class CommonSigner implements Signer {
    private final JWSSigner delegate;
    private final String keyId;
    private String keyURL;

    public CommonSigner(String keyId, String signingKey, String keyURL) {
        if (signingKey == null) {
            throw new IllegalArgumentException(signingKey);
        } else if (isAssymetricKey(signingKey)) {
            try {
                delegate = new RSASSASigner(JWK.parseFromPEMEncodedObjects(signingKey).toRSAKey().toPrivateKey(), true);
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        } else {
            try {
                delegate = new MACSigner(signingKey);
            } catch (KeyLengthException e) {
                throw new RuntimeException(e);
            }
        }

        this.keyId = keyId;
        this.keyURL = keyURL;
    }


    private static boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }

    @Override
    public String keyId() {
        return keyId;
    }

    @Override
    public String keyURL() {
        return keyURL;
    }


    public byte[] sign(byte[] bytes) {
        return null;//delegate.sign(bytes);
    }


    public String algorithm() {
        return delegate instanceof RSASSASigner ? "RS256": "HS256";//JwtAlgorithms.sigAlg(delegate.algorithm());
    }

    public String getJavaAlgorithm() {
        return "";//delegate.algorithm();
    }
}
