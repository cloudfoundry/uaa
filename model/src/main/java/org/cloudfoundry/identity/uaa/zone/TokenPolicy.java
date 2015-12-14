package org.cloudfoundry.identity.uaa.zone;

import java.util.Map;

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
    private int accessTokenValidity;
    private int refreshTokenValidity;
    private Map<String, KeyPair> keys;

    public TokenPolicy() {
        accessTokenValidity = refreshTokenValidity = -1;
    }

    public TokenPolicy(int accessTokenValidity, int refreshTokenValidity) {
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    public TokenPolicy(int accessTokenValidity, int refreshTokenValidity, KeyPairsMap keyPairsMap) {
        this(accessTokenValidity, refreshTokenValidity);

        keys = keyPairsMap.getKeys();
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

    public Map<String, KeyPair> getKeys() { return this.keys; }

    public void setKeys(Map<String, KeyPair> keys) { this.keys = keys; }

}
