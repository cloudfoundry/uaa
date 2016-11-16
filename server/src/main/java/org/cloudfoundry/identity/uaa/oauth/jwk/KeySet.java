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

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.Collections;
import java.util.List;

@JsonDeserialize(using = KeySetDeserializer.class)
@JsonSerialize(using = KeySetSerializer.class)
public class KeySet {

    private final List<JsonWebKey> keys;

    public KeySet(List<JsonWebKey> keys) {
        this.keys = Collections.unmodifiableList(keys);
    }

    public List<JsonWebKey> getKeys() {
        return keys;
    }
}
