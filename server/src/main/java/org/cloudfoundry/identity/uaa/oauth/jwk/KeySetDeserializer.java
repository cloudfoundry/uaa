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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.stream.Collectors;

public class KeySetDeserializer extends JsonDeserializer<KeySet> {

    @Override
    public KeySet deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        JsonNode node = JsonUtils.readTree(p);
        ArrayNode keys = (ArrayNode) node.get("keys");
        if (keys==null) {
            throw new JsonParseException(p, "keys attribute cannot be null");
        }
        LinkedHashSet<JsonWebKey> result = new LinkedHashSet<>();
        for (int i=0; i<keys.size(); i++) {
            Map<String, Object> map = JsonUtils.getNodeAsMap(keys.get(i));
            RsaJsonWebKey key = new RsaJsonWebKey(map);
            result.remove(key);
            result.add(key);
        }
        return new KeySet(result.stream().collect(Collectors.toList()));
    }

}
