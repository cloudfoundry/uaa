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
package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.impl.config.LegacyTokenKey;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.springframework.util.StringUtils;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;

public class KeyInfoService {
    private final String uaaBaseURL;

    public KeyInfoService(String uaaBaseURL) {
        this.uaaBaseURL = uaaBaseURL;
    }

    public KeyInfo getKey(String keyId, String sigAlg) {
        return getKeys(sigAlg).get(keyId);
    }

    public KeyInfo getKey(String keyId) {
        return getKeys().get(keyId);
    }

    public Map<String, KeyInfo> getKeys() {
        return getKeys(null);
    }

    public Map<String, KeyInfo> getKeys(String sigAlg) {
        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        if (config == null || config.getTokenPolicy().getKeys() == null || config.getTokenPolicy().getKeys().isEmpty()) {
            config = IdentityZoneHolder.getUaaZone().getConfig();
        }

        Map<String, KeyInfo> keys = new HashMap<>();
        for (Map.Entry<String, TokenPolicy.KeyInformation> entry : config.getTokenPolicy().getKeys().entrySet()) {
            KeyInfo keyInfo = KeyInfoBuilder.build(entry.getKey(), entry.getValue().getSigningKey(), addSubdomainToUrl(uaaBaseURL, IdentityZoneHolder.get().getSubdomain()),
                    sigAlg != null ? sigAlg : entry.getValue().getSigningAlg(),
                    entry.getValue().getSigningCert());
            keys.put(entry.getKey(), keyInfo);
        }

        if (keys.isEmpty()) {
            keys.put(LegacyTokenKey.LEGACY_TOKEN_KEY_ID, LegacyTokenKey.getLegacyTokenKeyInfo());
        }

        return keys;
    }

    public KeyInfo getActiveKey() {
        return getKeys().get(getActiveKeyId());
    }

    private String getActiveKeyId() {
        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        if (config == null) {
            return IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
        }
        String activeKeyId = config.getTokenPolicy().getActiveKeyId();

        Map<String, KeyInfo> keys;
        if (!StringUtils.hasText(activeKeyId) && (keys = getKeys()).size() == 1) {
            activeKeyId = keys.keySet().stream().findAny().get();
        }

        if (!StringUtils.hasText(activeKeyId)) {
            activeKeyId = IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
        }

        if (!StringUtils.hasText(activeKeyId)) {
            activeKeyId = LegacyTokenKey.LEGACY_TOKEN_KEY_ID;
        }

        return activeKeyId;
    }

    public String getTokenEndpointUrl() throws URISyntaxException {
        return UaaTokenUtils.constructTokenEndpointUrl(uaaBaseURL, IdentityZoneHolder.get());
    }
}
