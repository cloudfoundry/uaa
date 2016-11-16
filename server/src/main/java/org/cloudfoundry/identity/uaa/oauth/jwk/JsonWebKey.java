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


import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public abstract class JsonWebKey {

    enum KeyUse {
        sig,
        enc
    }

    enum KeyType {
        RSA
    }

    enum KeyOperation {
        sign,
        verify,
        encrypt,
        decrypt,
        wrapKey,
        unwrapKey,
        deriveKey,
        deriveBits
    }

    private final Map<String, Object> json;

    protected JsonWebKey(Map<String, Object> json) {
        if (json.get("kty")==null) {
            throw new IllegalArgumentException("kty field is required");
        }
        KeyType.valueOf((String) json.get("kty"));
        this.json = new HashMap(json);
    }

    public Map<String,Object> getKeyProperties() {
        return Collections.unmodifiableMap(json);
    }

    public final KeyType getKty() {
        return KeyType.valueOf((String) getKeyProperties().get("kty"));
    }

    public final String getKid() {
        return (String) getKeyProperties().get("kid");
    }

    public JsonWebKey setKid(String kid) {
        this.json.put("kid", kid);
        return this;
    }

    public final KeyUse getUse() {
        return KeyUse.valueOf((String) getKeyProperties().get("use"));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JsonWebKey)) return false;
        JsonWebKey that = (JsonWebKey) o;
        return getKid() != null ? getKid().equals(that.getKid()) : that.getKid() == null && getKeyProperties().equals(that.getKeyProperties());
    }

    @Override
    public int hashCode() {
        if (getKid()==null) {
            return getKty().hashCode();
        } else {
            return getKid().hashCode();
        }
    }

    abstract PublicKey getPublicKey();

}
