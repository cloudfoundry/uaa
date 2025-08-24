/*
 * *****************************************************************************
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

import com.fasterxml.jackson.annotation.*;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenPolicy {
    private static final Collector<? super Map.Entry<String, KeyInformation>, ?, ? extends Map<String, KeyInformation>> outputCollector = Collectors.toMap(Map.Entry::getKey, e -> {
        KeyInformation keyInformation = new KeyInformation();
        keyInformation.setSigningKey(e.getValue().getSigningKey());
        keyInformation.setSigningCert(e.getValue().getSigningCert());
        keyInformation.setSigningAlg(e.getValue().getSigningAlg());
        return keyInformation;
    });
    private static final Collector<? super Map.Entry<String, KeyInformation>, ?, ? extends Map<String, KeyInformation>> inputCollector
            = Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue);

    private int accessTokenValidity;
    private int refreshTokenValidity;
    private boolean jwtRevocable;
    private boolean refreshTokenUnique;
    private boolean refreshTokenRotate;
    private String refreshTokenFormat = OPAQUE.getStringValue();

    @JsonGetter("keys")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Map<String, KeyInformation> getKeysLegacy() {
        Map<String, KeyInformation> keyInformationMap = getKeys();
        return keyInformationMap == null || keyInformationMap.isEmpty() ? null : keyInformationMap.entrySet().stream().collect(outputCollector);
    }

    @JsonSetter("keys")
    private void setKeysLegacy(Map<String, KeyInformation> keyInformationMap) {
        setKeyInformation(keyInformationMap == null ? null : keyInformationMap.entrySet().stream().collect(inputCollector));
    }

    private Map<String, KeyInformation> keys;
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
        setKeysLegacy(signingKeysMap.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> {
            KeyInformation keyInformation = new KeyInformation();
            keyInformation.setSigningKey(e.getValue().get("signingKey"));
            keyInformation.setSigningCert(e.getValue().get("signingCert"));
            keyInformation.setSigningAlg(e.getValue().get("signingAlg"));
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
    public Map<String, KeyInformation> getKeys() {
        return this.keys == null ? Collections.emptyMap() : new HashMap<>(this.keys);
    }

    @JsonIgnore
    public void setKeyInformation(Map<String, KeyInformation> keys) {
        if (keys != null) {
            keys.forEach((key, value) -> {
                if (!StringUtils.hasText(value.getSigningKey()) || !StringUtils.hasText(key)) {
                    throw new IllegalArgumentException("KeyId and Signing key should not be null or empty");
                }
            });
        }
        this.keys = keys == null ? null : new HashMap<>(keys);
    }

    @JsonIgnore
    public void setKeys(Map<String, String> keys) {
        if (keys != null) {
            setKeyInformation(keys.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> {
                TokenPolicy.KeyInformation keyInformation = new TokenPolicy.KeyInformation();
                keyInformation.setSigningKey(e.getValue());
                return keyInformation;
            })
            ));
        }
    }

    public boolean isRefreshTokenUnique() {
        return refreshTokenUnique;
    }

    public void setRefreshTokenUnique(boolean refreshTokenUnique) {
        this.refreshTokenUnique = refreshTokenUnique;
    }

    public boolean isRefreshTokenRotate() {
        return refreshTokenRotate;
    }

    public void setRefreshTokenRotate(boolean refreshTokenRotate) {
        this.refreshTokenRotate = refreshTokenRotate;
    }

    public String getRefreshTokenFormat() {
        return refreshTokenFormat;
    }

    public void setRefreshTokenFormat(String refreshTokenFormat) {
        if (TokenConstants.TokenFormat.fromStringValue(refreshTokenFormat) == null) {
            List<String> validFormats = TokenConstants.TokenFormat.getStringValues();
            String message = "Invalid refresh token format %s. Acceptable values are: %s".formatted(refreshTokenFormat, validFormats.toString());
            throw new IllegalArgumentException(message);
        }
        this.refreshTokenFormat = refreshTokenFormat.toLowerCase();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class KeyInformation {
        private String signingKey;
        private String signingCert;
        private String signingAlg;

        public String getSigningCert() {
            return this.signingCert;
        }

        public void setSigningCert(String signingCert) {
            this.signingCert = signingCert;
        }

        public String getSigningAlg() {
            return this.signingAlg;
        }

        public void setSigningAlg(String signingAlg) {
            this.signingAlg = signingAlg;
        }

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
