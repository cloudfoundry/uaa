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

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;

public class CommonSigner implements Signer {

    private final org.springframework.security.jwt.crypto.sign.Signer delegate;
    private final String keyId;

    public CommonSigner(String keyId, String signingKey) {
        org.springframework.security.jwt.crypto.sign.Signer signer;
        if (signingKey == null) {
            throw new IllegalArgumentException(signingKey);
        } else if(KeyInfo.isAssymetricKey(signingKey)) {
            signer = new RsaSigner(signingKey);
        } else {
            signer = new MacSigner(signingKey);
        }
        delegate = signer;
        this.keyId = keyId;
    }

    @Override
    public String keyId() {
        return keyId;
    }

    @Override
    public byte[] sign(byte[] bytes) {
        return delegate.sign(bytes);
    }

    @Override
    public String algorithm() {
        return JwtAlgorithms.sigAlg(delegate.algorithm());
    }

    public String getJavaAlgorithm() {
        return delegate.algorithm();
    }


}
