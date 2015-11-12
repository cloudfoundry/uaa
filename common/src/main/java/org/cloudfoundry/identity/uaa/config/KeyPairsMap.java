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

package org.cloudfoundry.identity.uaa.config;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by pivotal on 11/11/15.
 */
public class KeyPairsMap {

    private Map<String, KeyPair> keyPairs;

    public KeyPairsMap(Map<String, ? extends Map<String, String>> unparsedMap) {
        keyPairs = new HashMap<>();

        for (String id : unparsedMap.keySet()) {
            Map<String, String> keys = unparsedMap.get(id);
            KeyPair keyPair = new KeyPair(keys.get("signing-key"), keys.get("verification-key"));
            keyPairs.put(id, keyPair);
        }
    }

    public Map<String, KeyPair> getKeyPairs() {
        return keyPairs;
    }
}
