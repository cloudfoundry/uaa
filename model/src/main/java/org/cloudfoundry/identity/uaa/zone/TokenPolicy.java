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

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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

    @JsonGetter("keys")
    public Map<String, KeyInformation> getKeysLegacy() {
        Map<String, String> keys = getKeys();
        return keys == null ? null : keys.entrySet().stream().collect(outputCollector);
    }

    @JsonSetter("keys")
    public void setKeysLegacy(Map<String, KeyInformation> keys) {
        setKeys(keys == null ? null : keys.entrySet().stream().collect(inputCollector));
    }

    private Map<String, String> keys;
    private String primaryKeyId;

    public TokenPolicy() {
        accessTokenValidity = refreshTokenValidity = -1;
    }

    public TokenPolicy(int accessTokenValidity, int refreshTokenValidity) {
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    public TokenPolicy(int accessTokenValidity, int refreshTokenValidity, SigningKeysMap keyPairsMap) {
        this(accessTokenValidity, refreshTokenValidity);

        setKeys(keyPairsMap.getKeys());
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
        return this.keys == null ? null : new HashMap<>(this.keys);
    }

    @JsonIgnore
    public void setKeys(Map<String, String> keys) {
        if (keys != null) {
            keys.entrySet().stream().forEach(e -> {
                if (!StringUtils.hasText(e.getValue()) || !StringUtils.hasText(e.getKey())) {
                    throw new IllegalArgumentException("KeyId and Signing key should not be null or empty");
                }
            });
            Set<String> keyIds = keys.keySet();
            if (primaryKeyId == null || !keyIds.contains(primaryKeyId)) {
                Optional<String> firstKeyId = keyIds.stream().findFirst();
                if (firstKeyId.isPresent()) {
                    primaryKeyId = firstKeyId.get();
                }
            }
        }
        this.keys = keys == null ? null : new HashMap<>(keys);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class KeyInformation {
        private String signingKey;

        public String getSigningKey() {
            return signingKey;
        }

        public void setSigningKey(String signingKey) {
            this.signingKey = signingKey;
        }
    }

    public String getPrimaryKeyId() {
        return primaryKeyId;
    }

    public void setPrimaryKeyId(String primaryKeyId) {
        this.primaryKeyId = primaryKeyId;
    }

}