/*
 * ******************************************************************************
 *       Cloud Foundry Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *       This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *       You may not use this product except in compliance with the License.
 *
 *       This product includes a number of subcomponents with
 *       separate copyright notices and license terms. Your use of these
 *       subcomponents is subject to the terms and conditions of the
 *       subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import java.util.HashMap;
import java.util.Map;

public class SigningKeysMap {

    public static final String SIGNING_KEY = "signingKey";
    private Map<String, String> keys;

    public SigningKeysMap(Map<String, ? extends Map<String, String>> unparsedMap) {
        keys = new HashMap<>();
        for (String kid : unparsedMap.keySet()) {
            Map<String, String> keys = unparsedMap.get(kid);
            String keyPair = keys.get(SIGNING_KEY);
            this.keys.put(kid, keyPair);
        }
    }

    public Map<String, String> getKeys() {
        return keys;
    }
}
