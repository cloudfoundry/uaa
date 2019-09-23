/*******************************************************************************
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

import org.junit.Test;

import static org.junit.Assert.*;

public class ScimGroupMemberTests {

    private static final ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
    private static final ScimGroupMember m2 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
    private static final ScimGroupMember m3 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
    private static final ScimGroupMember m4 = new ScimGroupMember("m1", ScimGroupMember.Type.GROUP);
    private static final ScimGroupMember m5 = new ScimGroupMember("m1", ScimGroupMember.Type.GROUP);
    private static final ScimGroupMember m6 = new ScimGroupMember("m1", ScimGroupMember.Type.GROUP);
    private static final ScimGroupMember m7 = new ScimGroupMember("m2", ScimGroupMember.Type.USER);

    @Test
    public void testHashCode() {
        assertEquals(m1.hashCode(), new ScimGroupMember(m1.getMemberId(), m1.getType()).hashCode());
        assertEquals(m4.hashCode(), new ScimGroupMember(m1.getMemberId(), m4.getType()).hashCode());
        assertEquals(m1.hashCode(), m2.hashCode());
        assertEquals(m1.hashCode(), m3.hashCode());
        assertNotEquals(m1.hashCode(), m4.hashCode());
        assertNotEquals(m1.hashCode(), m5.hashCode());
        assertNotEquals(m1.hashCode(), m6.hashCode());
        assertNotEquals(m1.hashCode(), m7.hashCode());
    }

    @Test
    public void testEquals() {
        assertEquals(m1, new ScimGroupMember(m1.getMemberId(), m1.getType()));
        assertEquals(m3, new ScimGroupMember(m3.getMemberId(), m3.getType()));
        assertEquals(m6, new ScimGroupMember(m6.getMemberId(), m6.getType()));
        assertNotSame(m7, m1);
        assertEquals(m1, m2);
        assertEquals(m1, m3);
        assertNotSame(m1, m4);
        assertNotSame(m1, m5);
        assertNotSame(m1, m6);
    }
}
