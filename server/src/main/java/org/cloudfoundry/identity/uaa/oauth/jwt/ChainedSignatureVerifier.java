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
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class ChainedSignatureVerifier implements JWSVerifier {
    private final List<JWSVerifier> delegates;

    public ChainedSignatureVerifier(JsonWebKeySet<? extends JsonWebKey> keys) {
        if(keys == null || keys.getKeys() == null || keys.getKeys().isEmpty()) {
            throw new IllegalArgumentException("keys cannot be null or empty");
        }
        List<JWSVerifier> ds = new ArrayList<>(keys.getKeys().size());
        for (JsonWebKey key : keys.getKeys()) {
            ds.add(new CommonSignatureVerifier(key.getValue()));
        }
        delegates = Collections.unmodifiableList(ds);
    }

    public ChainedSignatureVerifier(List<JWSVerifier> delegates) {
        this.delegates = delegates;
    }

    public boolean verify(JWSObject jwsObject) {
        Exception last = new RuntimeException("No matching keys found.");
        for (JWSVerifier delegate : delegates) {
            try {
                if (jwsObject.verify(delegate)) {
                    //success
                    return true;
                }
            } catch (Exception e) {
                last = e;
            }
        }
        throw (last instanceof RuntimeException) ? (RuntimeException) last : new RuntimeException(last);
    }
    public void verify(byte[] content, byte[] signature) {
        Exception last = new RuntimeException("No matching keys found.");
        for (JWSVerifier delegate : delegates) {
            try {
                delegate.verify( new JWSHeader.Builder(JWSAlgorithm.RS256).build(), content, Base64URL.encode(signature));
                //success
                return;
            } catch (Exception e) {
                last = e;
            }
        }
        throw (last instanceof RuntimeException) ? (RuntimeException) last : new RuntimeException(last);
    }

    public String algorithm() {
        return null;
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
        return false;
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return ObjectUtils.isEmpty(delegates) ? delegates.stream().findAny().get().supportedJWSAlgorithms() : Set.of(JWSAlgorithm.HS256);
    }

    @Override
    public JCAContext getJCAContext() {
        return delegates.stream().findAny().get().getJCAContext();
    }
}
