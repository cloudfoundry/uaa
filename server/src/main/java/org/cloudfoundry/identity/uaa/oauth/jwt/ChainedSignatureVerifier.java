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

import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ChainedSignatureVerifier implements Verifier {
    private final List<SignatureVerifier> delegates;

    public ChainedSignatureVerifier(JsonWebKeySet<? extends JsonWebKey> keys) {
        if (keys == null || keys.getKeys() == null || keys.getKeys().isEmpty()) {
            throw new IllegalArgumentException("keys cannot be null or empty");
        }
        List<SignatureVerifier> ds = new ArrayList<>(keys.getKeys().size());
        for (JsonWebKey key : keys.getKeys()) {
            ds.add(new SignatureVerifier(key));
        }
        delegates = Collections.unmodifiableList(ds);
    }

    public ChainedSignatureVerifier(List<SignatureVerifier> delegates) {
        this.delegates = delegates;
    }

    public String algorithm() {
        return null;
    }

    public List<SignatureVerifier> getDelegates() {
        return delegates;
    }
}
