/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSetter;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collector;
import java.util.stream.Collectors;

public class TokenPolicy {
    private static final Collector<? super Map.Entry<String, String>, ?, ? extends Map<String, KeyInformation>> outputCollector = Collectors.toMap(e -> e.getKey(), e -> {
        KeyInformation keyInformation = new KeyInformation();
        keyInformation.setSigningKey(e.getValue());
        return keyInformation;
    });
    private static final Collector<? super Map.Entry<String, KeyInformation>, ?, ? extends Map<String, String>> inputCollector
        = Collectors.toMap(e -> e.getKey(), e -> e.getValue().getSigningKey());

    private int accessTokenValidity;
    private int refreshTokenValidity;
    private boolean jwtRevocable = false;

    @JsonGetter("keys")
    private Map<String, KeyInformation> getKeysLegacy() {
        Map<String, String> keys = getKeys();
        return keys == null ? null : keys.entrySet().stream().collect(outputCollector);
    }

    @JsonSetter("keys")
    private void setKeysLegacy(Map<String, KeyInformation> keys) {
        setKeys(keys == null ? null : keys.entrySet().stream().collect(inputCollector));
    }

    private Map<String, String> keys;
    private String activeKeyId;

    public TokenPolicy() {
        accessTokenValidity = refreshTokenValidity = -1;
    }

    public TokenPolicy(int accessTokenValidity, int refreshTokenValidity) {
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    public TokenPolicy(int accessTokenValidity, int refreshTokenValidity, Map<String, ? extends Map<String, String>> signingKeysMap) {
        this(accessTokenValidity, refreshTokenValidity);
        setKeysLegacy(signingKeysMap.entrySet().stream().collect(Collectors.toMap(e -> e.getKey(), e -> {
            KeyInformation keyInformation = new KeyInformation();
            keyInformation.setSigningKey(e.getValue().get("signingKey"));
            return keyInformation;
        })));
    }

    public int getAccessTokenValidity() {
        return accessTokenValidity;
    }

    public void setAccessTokenValidity(int accessTokenValidity) {
        this.accessTokenValidity = accessTokenValidity;
    }

    public int getRefreshTokenValidity() {
        return refreshTokenValidity;
    }

    public void setRefreshTokenValidity(int refreshTokenValidity) {
        this.refreshTokenValidity = refreshTokenValidity;
    }

    @JsonIgnore
    public Map<String, String> getKeys() {
        return this.keys == null ? Collections.emptyMap() : new HashMap<>(this.keys);
    }

    @JsonIgnore
    public void setKeys(Map<String, String> keys) {
        if (keys != null) {
            keys.entrySet().stream().forEach(e -> {
                if (!StringUtils.hasText(e.getValue()) || !StringUtils.hasText(e.getKey())) {
                    throw new IllegalArgumentException("KeyId and Signing key should not be null or empty");
                }
            });
        }
        this.keys = keys == null ? null : new HashMap<>(keys);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class KeyInformation {
        private String signingKey;

        public String getSigningKey() {
            return signingKey;
        }

        public void setSigningKey(String signingKey) {
            this.signingKey = signingKey;
        }
    }

    public String getActiveKeyId() {
        return activeKeyId;
    }

    public void setActiveKeyId(String activeKeyId) {
        this.activeKeyId = activeKeyId;
    }

    public boolean isJwtRevocable() {
        return jwtRevocable;
    }

    public void setJwtRevocable(boolean jwtRevocable) {
        this.jwtRevocable = jwtRevocable;
    }
}
