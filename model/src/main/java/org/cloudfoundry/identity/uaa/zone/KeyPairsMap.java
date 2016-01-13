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

import static org.cloudfoundry.identity.uaa.zone.KeyPair.SIGNING_KEY;
import static org.cloudfoundry.identity.uaa.zone.KeyPair.SIGNING_KEY_PASSWORD;
import static org.cloudfoundry.identity.uaa.zone.KeyPair.VERIFICATION_KEY;

public class KeyPairsMap {


    private Map<String, KeyPair> keys;

    public KeyPairsMap(Map<String, ? extends Map<String, String>> unparsedMap) {
        keys = new HashMap<>();

        for (String kid : unparsedMap.keySet()) {
            Map<String, String> keys = unparsedMap.get(kid);
            KeyPair keyPair = new KeyPair(keys.get(SIGNING_KEY), keys.get(VERIFICATION_KEY), keys.get(SIGNING_KEY_PASSWORD));
            this.keys.put(kid, keyPair);
        }
    }

    public Map<String, KeyPair> getKeys() {
        return keys;
    }
}
