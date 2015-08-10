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
import org.junit.Assert;
import org.junit.Test;

public class UaaAuthenticationSerializationTests {

    @Test
    public void testDeserializationWithoutAuthenticatedTime() throws Exception {
        String data ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"authenticatedTime\":1438649464353,\"name\":\"username\"}";
        UaaAuthentication authentication1 = JsonUtils.readValue(data, UaaAuthentication.class);
        Assert.assertEquals(1438649464353l, authentication1.getAuthenticatedTime());

        String dataWithoutTime ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"name\":\"username\"}";
        UaaAuthentication authentication2 = JsonUtils.readValue(dataWithoutTime, UaaAuthentication.class);
        Assert.assertEquals(-1, authentication2.getAuthenticatedTime());

    }
}