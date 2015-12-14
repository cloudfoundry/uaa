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

/**
 * Created by pivotal on 11/11/15.
 */
public class KeyPairsMap {

    private Map<String, KeyPair> keys;

    public KeyPairsMap(Map<String, ? extends Map<String, String>> unparsedMap) {
        keys = new HashMap<>();

        for (String kid : unparsedMap.keySet()) {
            Map<String, String> keys = unparsedMap.get(kid);
            KeyPair keyPair = new KeyPair(keys.get("signingKey"), keys.get("verificationKey"));
            this.keys.put(kid, keyPair);
        }
    }

    public Map<String, KeyPair> getKeys() {
        return keys;
    }
}
