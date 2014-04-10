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

import java.io.IOException;
import java.util.Map.Entry;

import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.JsonSerializer;
import org.codehaus.jackson.map.SerializerProvider;

/**
 * @author Dave Syer
 * 
 */
public class UaaExceptionSerializer extends JsonSerializer<UaaException> {

    @Override
    public void serialize(UaaException value, JsonGenerator jgen, SerializerProvider provider) throws IOException,
                    JsonProcessingException {
        jgen.writeStartObject();
        jgen.writeStringField("error", value.getErrorCode());
        jgen.writeStringField("error_description", value.getMessage());
        if (value.getAdditionalInformation() != null) {
            for (Entry<String, String> entry : value.getAdditionalInformation().entrySet()) {
                String key = entry.getKey();
                String add = entry.getValue();
                jgen.writeStringField(key, add);
            }
        }
        jgen.writeEndObject();
    }

}
