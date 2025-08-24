/*
 * *****************************************************************************
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
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ScimGroupMemberTests {

    private static final ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
    private static final ScimGroupMember m2 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
    private static final ScimGroupMember m3 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
    private static final ScimGroupMember m4 = new ScimGroupMember("m1", ScimGroupMember.Type.GROUP);
    private static final ScimGroupMember m5 = new ScimGroupMember("m1", ScimGroupMember.Type.GROUP);
    private static final ScimGroupMember m6 = new ScimGroupMember("m1", ScimGroupMember.Type.GROUP);
    private static final ScimGroupMember m7 = new ScimGroupMember("m2", ScimGroupMember.Type.USER);

    @Test
    void testHashCode() {
        assertThat(new ScimGroupMember(m1.getMemberId(), m1.getType())).hasSameHashCodeAs(m1);
        assertThat(new ScimGroupMember(m1.getMemberId(), m4.getType())).hasSameHashCodeAs(m4);
        assertThat(m2).hasSameHashCodeAs(m1);
        assertThat(m3).hasSameHashCodeAs(m1);
        assertThat(m1).doesNotHaveSameHashCodeAs(m4)
                .doesNotHaveSameHashCodeAs(m5)
                .doesNotHaveSameHashCodeAs(m6)
                .doesNotHaveSameHashCodeAs(m7);
    }

    @Test
    void equals() {
        assertThat(new ScimGroupMember(m1.getMemberId(), m1.getType())).isEqualTo(m1);
        assertThat(new ScimGroupMember(m3.getMemberId(), m3.getType())).isEqualTo(m3);
        assertThat(new ScimGroupMember(m6.getMemberId(), m6.getType())).isEqualTo(m6);
        assertThat(m7).isNotSameAs(m1);
        assertThat(m2).isEqualTo(m1);
        assertThat(m3).isEqualTo(m1);
        assertThat(m1).isNotSameAs(m4)
                .isNotSameAs(m5)
                .isNotSameAs(m6);
    }
}
