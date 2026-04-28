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

import tools.jackson.core.JsonGenerator;

import java.util.Map;

import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

/**
 * See https://tools.ietf.org/html/rfc7517
 */

public class JsonWebKeySerializer extends ValueSerializer<JsonWebKey> {
    @Override
    public void serialize(JsonWebKey value, JsonGenerator gen, SerializationContext serializers) {
        gen.writeStartObject();
        for (Map.Entry<String, Object> entry : value.getKeyProperties().entrySet()) {
            gen.writeName(entry.getKey());
            gen.writePOJO(entry.getValue());
        }
        gen.writeEndObject();
    }
}
