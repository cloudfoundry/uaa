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

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.ValueDeserializer;

/**
 * JSON deserializer for Jackson to handle regular date instances as timestamps
 * in ISO format.
 */
public class JsonDateDeserializer extends ValueDeserializer<Date> {

    public static final String DATE_FORMATTER = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

    @Override
    public Date deserialize(JsonParser parser, DeserializationContext context) {
        return getDate(parser.getString(), parser);
    }

    public static Date getDate(String text, JsonParser parser) {
        try {
            return new SimpleDateFormat(DATE_FORMATTER).parse(text);
        } catch (ParseException e) {
            throw new StreamReadException(parser, "Could not parse date:" + text, e);
        }
    }

}
