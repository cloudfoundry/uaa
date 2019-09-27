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

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.util.Collections;


public class JsonWebKeyHelper {
    public static JsonWebKeySet<JsonWebKey> deserialize(String s) {
        if (!s.contains("\"keys\"")) {
            return new JsonWebKeySet<>(Collections.singletonList(JsonUtils.readValue(s, JsonWebKey.class)));
        } else {
            return JsonUtils.readValue(s, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
            });
        }
    }
}
