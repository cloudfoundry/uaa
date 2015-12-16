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
package org.cloudfoundry.identity.uaa.error;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;


/**
 * @author Dave Syer
 *
 */
public class UaaExceptionDeserializer extends JsonDeserializer<UaaException> {

    @Override
    public UaaException deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
        JsonProcessingException {

        int status = 400;

        JsonToken t = jp.getCurrentToken();
        if (t == JsonToken.START_OBJECT) {
            t = jp.nextToken();
        }
        Map<String, String> errorParams = new HashMap<String, String>();
        for (; t == JsonToken.FIELD_NAME; t = jp.nextToken()) {
            // Must point to field name
            String fieldName = jp.getCurrentName();
            // And then the value...
            t = jp.nextToken();
            // Note: must handle null explicitly here; value deserializers won't
            String value;
            if (t == JsonToken.VALUE_NULL) {
                value = null;
            }
            else {
                value = jp.getText();
                if (fieldName.equals("status")) {
                    try {
                        status = Integer.valueOf(value);
                    } catch (NumberFormatException e) {
                        // ignore
                    }
                }
            }
            errorParams.put(fieldName, value);
        }

        String errorCode = errorParams.get("error");
        String errorMessage = errorParams.containsKey("error_description") ? errorParams.get("error_description")
                        : null;
        if (errorMessage == null) {
            errorMessage = errorCode == null ? "UAA Error" : errorCode;
        }

        UaaException ex = new UaaException(errorCode, errorMessage, status);

        Set<Map.Entry<String, String>> entries = errorParams.entrySet();
        for (Map.Entry<String, String> entry : entries) {
            String key = entry.getKey();
            if (!"error".equals(key) && !"error_description".equals(key) && !"status".equals(key)) {
                ex.addAdditionalInformation(key, entry.getValue());
            }
        }

        return ex;

    }
}
