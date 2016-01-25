/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class ScimGroupTests {
    private static final String GROUP_BEFORE_DESCRIPTION = "{\"meta\":{\"version\":0,\"created\":\"2016-01-13T09:01:33.909Z\"},\"zoneId\":\"zoneId\",\"displayName\":\"name\",\"schemas\":[\"urn:scim:schemas:core:1.0\"],\"id\":\"id\"}";
    ScimGroup group;

    @Before
    public void setUp() {
        group = new ScimGroup("id","name","zoneId");
    }

    @Test
    public void testDeSerializeWithoutDescription() {
        group = JsonUtils.readValue(GROUP_BEFORE_DESCRIPTION, ScimGroup.class);
        assertEquals("id", group.getId());
        assertEquals("name", group.getDisplayName());
        assertEquals("zoneId", group.getZoneId());
        assertNull(group.getDescription());
    }

    @Test
    public void testSerializeWithDescription() {
        group.setDescription("description");
        String json = JsonUtils.writeValueAsString(group);
        group = JsonUtils.readValue(json, ScimGroup.class);
        assertEquals("id", group.getId());
        assertEquals("name", group.getDisplayName());
        assertEquals("zoneId", group.getZoneId());
        assertEquals("description", group.getDescription());
    }
}