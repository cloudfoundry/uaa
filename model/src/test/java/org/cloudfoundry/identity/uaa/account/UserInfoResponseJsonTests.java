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

package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.FAMILY_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GIVEN_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.LAST_LOGON_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PHONE_NUMBER;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class UserInfoResponseJsonTests {
    String json = "{\n" +
        "  \"multi_value\": [\n" +
        "    \"value1\",\n" +
        "    \"value2\"\n" +
        "  ],\n" +
        "  \"email\": \"olds@vmware.com\",\n" +
        "  \"name\": \"Dale Olds\",\n" +
        "  \"phone_number\": \"8505551234\",\n" +
        "  \"user_name\": \"olds\",\n" +
        "  \"given_name\": \"Dale\",\n" +
        "  \"family_name\": \"Olds\",\n" +
        "  \"sub\": \"12345\",\n" +
        "  \"number\": 123,\n" +
        "  \"origin\": \"uaa\",\n" +
        "  \"zid\": \"uaa\",\n" +
        "  \"single_value\": \"value3\",\n" +
        "  \"last_logon_time\": 1000\n" +
        "}";

    @Test
    public void deserializeTest() {
        UserInfoResponse response = JsonUtils.readValue(json, UserInfoResponse.class);
        assertEquals(Arrays.asList("value1", "value2"), response.getAttributeValues("multi_value"));
        assertEquals("value1", response.getAttributeValue("multi_value"));
        assertEquals(Arrays.asList("value3"), response.getAttributeValues("single_value"));
        assertEquals("value3", response.getAttributeValue("single_value"));
        assertEquals("olds@vmware.com", response.getAttributeValue(EMAIL));
        assertEquals("olds@vmware.com", response.getEmail());

        assertEquals("Dale", response.getAttributeValue(GIVEN_NAME));
        assertEquals("Dale", response.getGivenName());

        assertEquals("Olds", response.getAttributeValue(FAMILY_NAME));
        assertEquals("Olds", response.getFamilyName());

        assertNull(response.getAttributeValue(NAME));
        assertEquals("Dale Olds", response.getFullName());

        assertEquals("8505551234", response.getAttributeValue(PHONE_NUMBER));
        assertEquals("8505551234", response.getPhoneNumber());

        assertNull(response.getAttributeValue(SUB));
        assertEquals("12345", response.getUserId());

        assertEquals("olds", response.getAttributeValue(USER_NAME));
        assertEquals("olds", response.getUsername());

        assertEquals(1000L, response.getAttributeValue(LAST_LOGON_TIME));

    }

    @Test
    public void serializeTest() {
        UserInfoResponse response = JsonUtils.readValue(json, UserInfoResponse.class);
        json = JsonUtils.writeValueAsString(response);
        deserializeTest();
    }
}
