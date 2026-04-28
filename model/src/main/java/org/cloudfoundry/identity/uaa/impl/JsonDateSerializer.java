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

import tools.jackson.core.JsonGenerator;

import java.text.SimpleDateFormat;
import java.util.Date;

import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

import static org.cloudfoundry.identity.uaa.impl.JsonDateDeserializer.DATE_FORMATTER;

/**
 * JSON serializer for Jackson to handle regular date instances as timestamps in
 * ISO format.
 */
public class JsonDateSerializer extends ValueSerializer<Date> {

    @Override
    public void serialize(Date date, JsonGenerator generator, SerializationContext provider) {
        String formatted = new SimpleDateFormat(DATE_FORMATTER).format(date);
        generator.writeString(formatted);
    }

}
