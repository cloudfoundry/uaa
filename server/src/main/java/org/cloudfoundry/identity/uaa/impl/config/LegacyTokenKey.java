package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.springframework.util.StringUtils;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public final class LegacyTokenKey {
    private LegacyTokenKey() {}

    public static final String LEGACY_TOKEN_KEY_ID = "legacy-token-key";

    private static String legacySigningKey = null;
    private static KeyInfo keyInfo;
    static {
        setLegacySigningKey(legacySigningKey);
    }

    public static void setLegacySigningKey(String legacySigningKey) {
        if(!StringUtils.hasText(legacySigningKey)) {
            return;
        }

        LegacyTokenKey.legacySigningKey = legacySigningKey;
        LegacyTokenKey.keyInfo = new KeyInfo();
        LegacyTokenKey.keyInfo.setKeyId(LEGACY_TOKEN_KEY_ID);
        LegacyTokenKey.keyInfo.setSigningKey(legacySigningKey);
    }

    public static String getLegacySigningKey() {
        return legacySigningKey;
    }

    public static KeyInfo getLegacyTokenKeyInfo() {
        return keyInfo;
    }
}
