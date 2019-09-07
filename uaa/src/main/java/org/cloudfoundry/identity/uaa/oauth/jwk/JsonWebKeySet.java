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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * See https://tools.ietf.org/html/rfc7517
 */
public class JsonWebKeySet<T extends JsonWebKey> {

    private final List<T> keys;

    public JsonWebKeySet(@JsonProperty("keys") List<T> keys) {
        Set<T> set = new LinkedHashSet<>();
        //rules for how to override duplicates
        for (T key : keys) {
            if(key == null) continue;
            set.remove(key);
            set.add(key);
        }
        this.keys = new LinkedList(set);
    }

    public List<T> getKeys() {
        return Collections.unmodifiableList(keys);
    }
}
