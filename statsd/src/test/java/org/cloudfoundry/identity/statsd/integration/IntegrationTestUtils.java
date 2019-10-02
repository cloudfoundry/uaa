/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.statsd.integration;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class IntegrationTestUtils {

    public static final String UAA_BASE_URL = "http://localhost:8080/uaa";
    public static final String TEST_USERNAME = "marissa";
    public static final String TEST_PASSWORD = "koala";
    static final String CSRF_PARAMETER_NAME = "_csrf";
    private static final Pattern CSRF_FORM_ELEMENT = Pattern.compile(
            "\\<input type=\\\"hidden\\\" name=\\\"" + CSRF_PARAMETER_NAME + "\\\" value=\\\"(.*?)\\\""
    );

    public static String extractCsrfToken(String body) {
        Matcher matcher = CSRF_FORM_ELEMENT.matcher(body);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    public static long getStatsDValueFromMessage(String message) {
        assertNotNull(message);

        String[] parts = message.split("[:|]");
        assertTrue(parts[2].equals("g") || parts[2].equals("c"));

        return Long.valueOf(parts[1]);
    }

    public static long getTimeValueFromMessage(String message) {
        assertNotNull(message);

        String[] parts = message.split("[:|]");
        assertEquals(parts[2], "ms");

        return Long.valueOf(parts[1]);
    }

}
