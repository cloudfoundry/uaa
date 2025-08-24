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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class ScimGroupTests {
    private static final String GROUP_BEFORE_DESCRIPTION = "{\"meta\":{\"version\":0,\"created\":\"2016-01-13T09:01:33.909Z\"},\"zoneId\":\"zoneId\",\"displayName\":\"name\",\"schemas\":[\"urn:scim:schemas:core:1.0\"],\"id\":\"id\"}";
    ScimGroup group;
    private ScimGroup patch;
    private ScimGroupMember member1;
    private ScimGroupMember member2;
    private ScimGroupMember member3;

    @BeforeEach
    void setUp() {
        group = new ScimGroup("id", "name", "zoneId");
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
    void deSerializeWithoutDescription() {
        group = JsonUtils.readValue(GROUP_BEFORE_DESCRIPTION, ScimGroup.class);
        assertThat(group.getId()).isEqualTo("id");
        assertThat(group.getDisplayName()).isEqualTo("name");
        assertThat(group.getZoneId()).isEqualTo("zoneId");
        assertThat(group.getDescription()).isNull();
    }

    @Test
    void serializeWithDescription() {
        group.setDescription("description");
        String json = JsonUtils.writeValueAsString(group);
        group = JsonUtils.readValue(json, ScimGroup.class);
        assertThat(group.getId()).isEqualTo("id");
        assertThat(group.getDisplayName()).isEqualTo("name");
        assertThat(group.getZoneId()).isEqualTo("zoneId");
        assertThat(group.getDescription()).isEqualTo("description");
    }

    @Test
    void patch() {
        group.patch(patch);
        assertThat(group.getId()).isEqualTo(patch.getId());
        assertThat(group.getDisplayName()).isEqualTo("NewName");
        assertThat(group.getDescription()).isEqualTo("NewDescription");
    }

    @Test
    void patchZoneIdFails() {
        group.setZoneId("uaa");
        patch.setZoneId("zoneid");

        assertThat(group.getZoneId()).isEqualTo("uaa");
        assertThat(patch.getZoneId()).isEqualTo("zoneid");

        group.patch(patch);

        assertThat(group.getZoneId()).isEqualTo("uaa");
        assertThat(patch.getZoneId()).isEqualTo("zoneid");
    }

    @Test
    void patchDeleteMetaAttributes() {
        assertThat(group.getDescription()).isEqualTo("description");
        String[] attributes = new String[]{"description"};
        patch.getMeta().setAttributes(attributes);
        group.patch(patch);
        assertThat(group.getDescription()).isEqualTo("NewDescription");

        patch.setDescription(null);
        group.patch(patch);
        assertThat(group.getDescription()).isNull();
    }

    @Test
    void dropDisplayName() {
        patch.setDisplayName("NewDisplayName");
        group.setDisplayName("display");
        assertThat(group.getDisplayName()).isEqualTo("display");
        String[] attributes = new String[]{"displayname"};
        patch.getMeta().setAttributes(attributes);
        group.patch(patch);
        assertThat(group.getDisplayName()).isEqualTo("NewDisplayName");

        patch.setDisplayName(null);
        group.patch(patch);
        assertThat(group.getDisplayName()).isNull();
    }

    @Test
    void cant_drop_zone_id() {
        patch.getMeta().setAttributes(new String[]{"zoneID"});
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                group.patch(patch));
    }

    @Test
    void cant_drop_id() {
        patch.getMeta().setAttributes(new String[]{"id"});
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                group.patch(patch));
    }

    @Test
    void dropAllMembers() {
        group.setMembers(Arrays.asList(member1, member2, member3));
        assertThat(group.getMembers()).hasSize(3);
        patch.getMeta().setAttributes(new String[]{"members"});
        group.patch(patch);
        assertThat(group.getMembers()).isEmpty();
    }

    @Test
    void dropOneMembers() {
        group.setMembers(Arrays.asList(member1, member2, member3));
        ScimGroupMember member = new ScimGroupMember(member1.getMemberId());
        member.setOperation("DELETE");
        patch.setMembers(Collections.singletonList(
                member
        ));
        group.patch(patch);
        assertThat(group.getMembers()).hasSize(2);
    }

    @Test
    void dropAllMembersUsingOperation() {
        member1.setOperation("delete");
        member2.setOperation("delete");
        member3.setOperation("delete");
        group.setMembers(Arrays.asList(member1, member2, member3));
        patch.setMembers(group.getMembers());
        assertThat(group.getMembers()).hasSize(3);
        group.patch(patch);
        assertThat(group.getMembers()).isEmpty();
    }

    @Test
    void addAllMembers() {
        patch.setMembers(Arrays.asList(member1, member2, member3));
        group.setMembers(emptyList());
        assertThat(group.getMembers()).isEmpty();
        group.patch(patch);
        assertThat(group.getMembers()).hasSize(3);
    }

    @Test
    void addOneMember() {
        patch.setMembers(Collections.singletonList(member1));
        group.setMembers(Arrays.asList(member2, member3));
        assertThat(group.getMembers()).hasSize(2);
        group.patch(patch);
        assertThat(group.getMembers()).hasSize(3);
    }
}
