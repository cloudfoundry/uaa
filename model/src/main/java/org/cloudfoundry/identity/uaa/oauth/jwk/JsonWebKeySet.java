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

package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * See https://tools.ietf.org/html/rfc7517
 */
public class JsonWebKeySet<T extends JsonWebKey> {

    private static final String JSON_PROPERTY_KEYS = "keys";
    private final List<T> keys;

    public JsonWebKeySet(@JsonProperty(JSON_PROPERTY_KEYS) List<T> keys) {
        Set<T> set = new LinkedHashSet<>();
        //rules for how to override duplicates
        for (T key : keys) {
            if (key == null) {
                continue;
            }
            set.remove(key);
            set.add(key);
        }
        this.keys = new LinkedList<>(set);
    }

    public List<T> getKeys() {
        return Collections.unmodifiableList(keys);
    }

    @JsonIgnore
    public Map<String, Object> getKeySetMap() {
        Map<String, Object> keySet = new HashMap<>();
        ArrayList<Map<String, Object>> keyArray = new ArrayList<>();
        long keyCount = Optional.ofNullable(keys).orElseThrow(() -> new IllegalStateException("No keys found.")).stream()
                .map(k -> keyArray.add(k.getKeyProperties())).filter(Objects::nonNull).count();
        if (keyCount > 0) {
            keySet.put(JSON_PROPERTY_KEYS, keyArray);
        }
        return keySet;
    }
}
