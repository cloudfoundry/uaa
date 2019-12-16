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

import java.util.Arrays;
import java.util.Collections;

import static java.util.Collections.emptyList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class ScimGroupTests {
    private static final String GROUP_BEFORE_DESCRIPTION = "{\"meta\":{\"version\":0,\"created\":\"2016-01-13T09:01:33.909Z\"},\"zoneId\":\"zoneId\",\"displayName\":\"name\",\"schemas\":[\"urn:scim:schemas:core:1.0\"],\"id\":\"id\"}";
    ScimGroup group;
    private ScimGroup patch;
    private ScimGroupMember member1;
    private ScimGroupMember member2;
    private ScimGroupMember member3;

    @Before
    public void setUp() {
        group = new ScimGroup("id","name","zoneId");
        group.setDescription("description");

        patch = new ScimGroup();
        patch.setId(group.getId());
        patch.setDisplayName("NewName");
        patch.setDescription("NewDescription");

        member1 = new ScimGroupMember("id1");
        member2 = new ScimGroupMember("id2");
        member3 = new ScimGroupMember("id3");
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

    @Test
    public void testPatch(){
        group.patch(patch);
        assertEquals(patch.getId(), group.getId());
        assertEquals("NewName",group.getDisplayName());
        assertEquals("NewDescription", group.getDescription());
    }

    @Test
    public void testPatchZoneIdFails(){
        group.setZoneId("uaa");
        patch.setZoneId("zoneid");

        assertEquals("uaa", group.getZoneId());
        assertEquals("zoneid", patch.getZoneId());

        group.patch(patch);

        assertEquals("uaa", group.getZoneId());
        assertEquals("zoneid", patch.getZoneId());
    }

    @Test
    public void testPatchDeleteMetaAttributes(){
        assertEquals("description", group.getDescription());
        String[] attributes = new String[]{"description"};
        patch.getMeta().setAttributes(attributes);
        group.patch(patch);
        assertEquals("NewDescription", group.getDescription());

        patch.setDescription(null);
        group.patch(patch);
        assertNull(group.getDescription());
    }


    @Test
    public void testDropDisplayName(){
        patch.setDisplayName("NewDisplayName");
        group.setDisplayName("display");
        assertEquals("display", group.getDisplayName());
        String[] attributes = new String[]{"displayname"};
        patch.getMeta().setAttributes(attributes);
        group.patch(patch);
        assertEquals("NewDisplayName", group.getDisplayName());

        patch.setDisplayName(null);
        group.patch(patch);
        assertNull(group.getDisplayName());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cant_drop_zone_id() {
        patch.getMeta().setAttributes(new String[] {"zoneID"});
        group.patch(patch);
    }

    @Test(expected = IllegalArgumentException.class)
    public void cant_drop_id() {
        patch.getMeta().setAttributes(new String[] {"id"});
        group.patch(patch);
    }

    @Test
    public void testDropAllMembers(){
        group.setMembers(Arrays.asList(member1, member2, member3));
        assertEquals(3, group.getMembers().size());
        patch.getMeta().setAttributes(new String[] {"members"});
        group.patch(patch);
        assertEquals(0, group.getMembers().size());
    }

    @Test
    public void testDropOneMembers(){
        group.setMembers(Arrays.asList(member1, member2, member3));
        ScimGroupMember member = new ScimGroupMember(member1.getMemberId());
        member.setOperation("DELETE");
        patch.setMembers(Collections.singletonList(
                member
        ));
        group.patch(patch);
        assertEquals(2, group.getMembers().size());
    }

    @Test
    public void testDropAllMembersUsingOperation() {
        member1.setOperation("delete");
        member2.setOperation("delete");
        member3.setOperation("delete");
        group.setMembers(Arrays.asList(member1, member2, member3));
        patch.setMembers(group.getMembers());
        assertEquals(3, group.getMembers().size());
        group.patch(patch);
        assertEquals(0, group.getMembers().size());

    }

    @Test
    public void testAddAllMembers() {
        patch.setMembers(Arrays.asList(member1, member2, member3));
        group.setMembers(emptyList());
        assertEquals(0, group.getMembers().size());
        group.patch(patch);
        assertEquals(3, group.getMembers().size());

    }

    @Test
    public void testAddOneMember() {
        patch.setMembers(Collections.singletonList(member1));
        group.setMembers(Arrays.asList(member2, member3));
        assertEquals(2, group.getMembers().size());
        group.patch(patch);
        assertEquals(3, group.getMembers().size());

    }
}
