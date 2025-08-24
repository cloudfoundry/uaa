/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.impl;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * JSON deserializer for Jackson to handle regular date instances as timestamps
 * in ISO format.
 */
public class JsonDateDeserializer extends JsonDeserializer<Date> {

    public static final String DATE_FORMATTER = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

    @Override
    public Date deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        return getDate(parser.getText(), parser.getCurrentLocation());
    }

    public static Date getDate(String text, JsonLocation loc) throws IOException {
        try {
            return new SimpleDateFormat(DATE_FORMATTER).parse(text);
        } catch (ParseException e) {
            throw new JsonParseException("Could not parse date:" + text, loc, e);
        }
    }

}
