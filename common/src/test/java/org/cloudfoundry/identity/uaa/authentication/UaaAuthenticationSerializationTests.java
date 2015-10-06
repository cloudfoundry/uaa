/*
 * ******************************************************************************
 *  *     Cloud Foundry
 *  *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *  *
 *  *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  *     You may not use this product except in compliance with the License.
 *  *
 *  *     This product includes a number of subcomponents with
 *  *     separate copyright notices and license terms. Your use of these
 *  *     subcomponents is subject to the terms and conditions of the
 *  *     subcomponent's license, as noted in the LICENSE file.
 *  ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UaaAuthenticationSerializationTests {

    @Test
    public void testDeserializationWithoutAuthenticatedTime() throws Exception {
        String data ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"authenticatedTime\":1438649464353,\"name\":\"username\"}";
        UaaAuthentication authentication1 = JsonUtils.readValue(data, UaaAuthentication.class);
        assertEquals(1438649464353l, authentication1.getAuthenticatedTime());
        assertEquals(-1l, authentication1.getExpiresAt());
        assertTrue(authentication1.isAuthenticated());

        String dataWithoutTime ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"name\":\"username\"}";
        UaaAuthentication authentication2 = JsonUtils.readValue(dataWithoutTime, UaaAuthentication.class);
        assertEquals(-1, authentication2.getAuthenticatedTime());


        long inThePast = System.currentTimeMillis() - 1000l * 60l;
        data ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"authenticatedTime\":1438649464353,\"name\":\"username\", \"expiresAt\":"+inThePast+"}";
        UaaAuthentication authentication3 = JsonUtils.readValue(data, UaaAuthentication.class);
        assertEquals(1438649464353l, authentication3.getAuthenticatedTime());
        assertEquals(inThePast, authentication3.getExpiresAt());
        assertFalse(authentication3.isAuthenticated());

        long inTheFuture = System.currentTimeMillis() + 1000l * 60l;
        data ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"authenticatedTime\":1438649464353,\"name\":\"username\", \"expiresAt\":"+inTheFuture+"}";
        UaaAuthentication authentication4 = JsonUtils.readValue(data, UaaAuthentication.class);
        assertEquals(1438649464353l, authentication4.getAuthenticatedTime());
        assertEquals(inTheFuture, authentication4.getExpiresAt());
        assertTrue(authentication4.isAuthenticated());
    }
}