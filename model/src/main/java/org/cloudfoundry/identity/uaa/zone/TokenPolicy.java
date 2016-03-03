package org.cloudfoundry.identity.uaa.zone;

import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collector;
import java.util.stream.Collectors;

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

public class TokenPolicy {
    private static final Collector<? super Map.Entry<String, String>, ?, ? extends Map<String, KeyInformation>> inputCollector
            = Collectors.toMap(e -> e.getKey(), e -> new KeyInformation(e.getValue()));
    private static final Collector<? super Map.Entry<String, KeyInformation>, ?, ? extends Map<String, String>> outputCollector
            = Collectors.toMap(e -> e.getKey(), e -> e.getValue().getSigningKey());

    private int accessTokenValidity;
    private int refreshTokenValidity;
    private Map<String, KeyInformation> keys;
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

    public Map<String, String> getKeys() { return this.keys == null ? null : this.keys.entrySet().stream().collect(outputCollector); }

    public static class KeyInformation {
        private final String signingKey;

        public KeyInformation(String signingKey) {
            this.signingKey = signingKey;
        }

        public String getSigningKey() {
            return signingKey;
        }
    }
    public void setKeys(Map<String, String> keys) {
        this.keys = keys == null ? null : keys.entrySet().stream().collect(inputCollector);
        if(keys != null) {
            keys.entrySet().stream().forEach(e -> {
                if(!StringUtils.hasText(e.getValue()) || !StringUtils.hasText(e.getKey())) {
                    throw new IllegalArgumentException("KeyId and Signing key should not be null or empty");
                }
            });
            Set<String> keyIds = keys.keySet();
            if(primaryKeyId == null || !keyIds.contains(primaryKeyId)) {
                Optional<String> firstKeyId = keyIds.stream().findFirst();
                if(firstKeyId.isPresent()) {
                    primaryKeyId = firstKeyId.get();
                }
            }
        }
    }

    public String getPrimaryKeyId() {
        return primaryKeyId;
    }

    public void setPrimaryKeyId(String primaryKeyId) {
        this.primaryKeyId = primaryKeyId;
    }

}
