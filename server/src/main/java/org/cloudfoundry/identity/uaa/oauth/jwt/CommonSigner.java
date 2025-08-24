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
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;

import java.util.Optional;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;

public class CommonSigner implements Signer {

    private final JWSSigner delegate;
    private final String algorithm;
    private final String keyId;
    private final String keyURL;

    public CommonSigner(String keyId, String signingKey, String keyURL) {
        if (signingKey == null) {
            throw new IllegalArgumentException(signingKey);
        }
        KeyInfo keyInfo = new KeyInfo(keyId, signingKey, Optional.ofNullable(keyURL).orElse(DEFAULT_UAA_URL));
        this.delegate = keyInfo.getSigner();
        this.keyId = keyId;
        this.keyURL = keyURL;
        this.algorithm = keyInfo.algorithm();
    }

    public String keyId() {
        return keyId;
    }


    public String keyURL() {
        return keyURL;
    }

    public String algorithm() {
        return JwtAlgorithms.sigAlg(algorithm);
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        return delegate.sign(header, signingInput);
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
