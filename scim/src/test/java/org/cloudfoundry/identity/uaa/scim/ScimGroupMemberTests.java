/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupMemberInterface;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroupMember;
import org.junit.Test;

public class ScimGroupMemberTests {

    private static final ScimGroupMemberInterface m1 = new ScimGroupMember("m1", ScimGroupMemberInterface.Type.USER, null);
    private static final ScimGroupMemberInterface m2 = new ScimGroupMember("m1", ScimGroupMemberInterface.Type.USER,
                    ScimGroupMemberInterface.GROUP_ADMIN);
    private static final ScimGroupMemberInterface m3 = new ScimGroupMember("m1", ScimGroupMemberInterface.Type.USER,
                    ScimGroupMemberInterface.GROUP_MEMBER);
    private static final ScimGroupMemberInterface m4 = new ScimGroupMember("m1", ScimGroupMemberInterface.Type.GROUP,
                    ScimGroupMemberInterface.GROUP_MEMBER);
    private static final ScimGroupMemberInterface m5 = new ScimGroupMember("m1", ScimGroupMemberInterface.Type.GROUP,
                    ScimGroupMemberInterface.GROUP_ADMIN);
    private static final ScimGroupMemberInterface m6 = new ScimGroupMember("m1", ScimGroupMemberInterface.Type.GROUP, null);
    private static final ScimGroupMemberInterface m7 = new ScimGroupMember("m2", ScimGroupMemberInterface.Type.USER,
                    ScimGroupMemberInterface.GROUP_MEMBER);

    @Test
    public void testHashCode() throws Exception {
        assertTrue(m1.hashCode() == new ScimGroupMember(m1.getMemberId(), m1.getType(), m1.getRoles()).hashCode());
        assertTrue(m4.hashCode() == new ScimGroupMember(m1.getMemberId(), m4.getType(), m4.getRoles()).hashCode());
        assertTrue(m1.hashCode() == m2.hashCode());
        assertTrue(m1.hashCode() == m3.hashCode());
        assertFalse(m1.hashCode() == m4.hashCode());
        assertFalse(m1.hashCode() == m5.hashCode());
        assertFalse(m1.hashCode() == m6.hashCode());
        assertFalse(m1.hashCode() == m7.hashCode());
    }

    @Test
    public void testEquals() throws Exception {
        assertEquals(m1, new ScimGroupMember(m1.getMemberId(), m1.getType(), null));
        assertEquals(m3, new ScimGroupMember(m3.getMemberId(), m3.getType(), null));
        assertEquals(m6, new ScimGroupMember(m6.getMemberId(), m6.getType(), m3.getRoles()));
        assertNotSame(m7, m1);
        assertEquals(m1, m2);
        assertEquals(m1, m3);
        assertNotSame(m1, m4);
        assertNotSame(m1, m5);
        assertNotSame(m1, m6);
    }
}
