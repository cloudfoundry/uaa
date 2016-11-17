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
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.io.IOException;
import java.util.Map;

/**
 * See https://tools.ietf.org/html/rfc7517
 */
public class JsonWebKeyDeserializer extends JsonDeserializer<JsonWebKey> {
    @Override
    public JsonWebKey deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        JsonNode node = JsonUtils.readTree(p);
        Map<String, Object> map = JsonUtils.getNodeAsMap(node);
        if (map.get("kty")==null) {
            throw new JsonParseException(p, "kty is a required attribute on a JsonWebKey");
        }
        return new JsonWebKey(map);
    }
}
