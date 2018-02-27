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
import org.hamcrest.CoreMatchers;
import org.junit.Test;

import java.util.List;

import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class UserInfoResponseJsonTests {
    String json = "{\n" +
        "  \"email\": \"olds@vmware.com\",\n" +
        "  \"email_verified\": true,\n" +
        "  \"name\": \"Dale Olds\",\n" +
        "  \"phone_number\": \"8505551234\",\n" +
        "  \"user_name\": \"olds\",\n" +
        "  \"given_name\": \"Dale\",\n" +
        "  \"family_name\": \"Olds\",\n" +
        "  \"sub\": \"12345\",\n" +
        "  \"user_id\": \"12345\",\n" +
        "  \"number\": 123,\n" +
        "  \"origin\": \"uaa\",\n" +
        "  \"zid\": \"uaa\",\n" +
        "  \"user_attributes\": {\"Key 1\":[\"Val 11\",\"Val 12\"],\"Key 2\":[\"Val 21\",\"Val 22\"]}," +
        "  \"roles\": [\"role12\", \"role54\", \"role134\", \"role812\"]," +
        "  \"previous_logon_time\": 1000\n" +
        "}";

    @Test
    public void deserializeTest() {
        UserInfoResponse response = JsonUtils.readValue(json, UserInfoResponse.class);
        assertEquals("olds@vmware.com", response.getEmail());
        assertEquals("Dale", response.getGivenName());
        assertEquals("Olds", response.getFamilyName());
        assertEquals("Dale Olds", response.getFullName());
        assertEquals("8505551234", response.getPhoneNumber());
        assertEquals("12345", response.getUserId());
        assertEquals("12345", response.getSub());
        assertEquals("olds", response.getUserName());
        assertEquals(true, response.isEmailVerified());

        assertThat(
            response.getUserAttributes().get("Key 1"),
            hasItems(CoreMatchers.is("Val 11"), CoreMatchers.is("Val 12"))
        );
        assertThat(
            response.getUserAttributes().get("Key 2"),
            hasItems(CoreMatchers.is("Val 21"), CoreMatchers.is("Val 22"))
        );

        assertThat(
            response.getRoles(),
            hasItems(
                CoreMatchers.is("role12"),
                CoreMatchers.is("role54"),
                CoreMatchers.is("role134"),
                CoreMatchers.is("role812")
            )
        );
        assertEquals(Long.valueOf(1000L), response.previousLogonSuccess);
    }

    @Test
    public void serializeTest() {
        UserInfoResponse response = JsonUtils.readValue(json, UserInfoResponse.class);
        json = JsonUtils.writeValueAsString(response);
        deserializeTest();
    }
}
