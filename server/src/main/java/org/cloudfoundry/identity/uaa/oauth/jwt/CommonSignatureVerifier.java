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

import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;

public class CommonSignatureVerifier implements SignatureVerifier {
    private final SignatureVerifier delegate;

    public CommonSignatureVerifier(String verificationKey) {
        if(verificationKey == null) {
            throw new IllegalArgumentException("verificationKey cannot be null");
        } else if(isAssymetricKey(verificationKey)) {
            delegate = new RsaVerifier(verificationKey);
        } else {
            delegate = new MacSigner(verificationKey);
        }
    }

    private static boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }

    @Override
    public void verify(byte[] content, byte[] signature) {
        delegate.verify(content, signature);
    }

    @Override
    public String algorithm() {
        return delegate.algorithm();
    }
}
