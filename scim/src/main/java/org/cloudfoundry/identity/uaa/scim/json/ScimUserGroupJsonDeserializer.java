/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.json;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.scim.domain.common.ScimUserGroupInterface;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimUserGroup;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.JsonDeserializer;

public class ScimUserGroupJsonDeserializer extends JsonDeserializer<ScimUserGroupInterface> {

    @Override
    public ScimUserGroupInterface deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        ScimUserGroupInterface user = createObject();

        Map<String, Object> context = new HashMap<String, Object>();

        startDeserialization(user, context);

        while (jp.nextToken() != JsonToken.END_OBJECT) {
            if (jp.getCurrentToken() == JsonToken.FIELD_NAME) {
                String fieldName = jp.getCurrentName();
                jp.nextToken();

                deserializeField(user, fieldName, jp, context);
            }
        }

        endDeserialization(user, context);

        return user;
    }


    protected ScimUserGroupInterface createObject()
    {
        return new ScimUserGroup();
    }

    protected void startDeserialization(ScimUserGroupInterface user, Map<String, Object> context)
    {
    }

    protected void deserializeField(ScimUserGroupInterface user, String fieldName, JsonParser jp, Map<String, Object> context) throws JsonProcessingException, IOException
    {
        if ("value".equalsIgnoreCase(fieldName)) {
            user.setValue(jp.readValueAs(String.class));
        } else if ("display".equalsIgnoreCase(fieldName)) {
            user.setDisplay(jp.readValueAs(String.class));
        } else if ("type".equalsIgnoreCase(fieldName)) {
            user.setType(jp.readValueAs(ScimUserGroupInterface.Type.class));
        }
    }

    protected void endDeserialization (ScimUserGroupInterface user, Map<String, Object> context)
    {
    }


}
