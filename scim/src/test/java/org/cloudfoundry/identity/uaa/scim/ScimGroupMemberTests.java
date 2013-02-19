package org.cloudfoundry.identity.uaa.scim;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

public class ScimGroupMemberTests {

	private static final ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, null);
	private static final ScimGroupMember m2 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN);
	private static final ScimGroupMember m3 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER);
	private static final ScimGroupMember m4 = new ScimGroupMember("m1", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_MEMBER);
	private static final ScimGroupMember m5 = new ScimGroupMember("m1", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_ADMIN);
	private static final ScimGroupMember m6 = new ScimGroupMember("m1", ScimGroupMember.Type.GROUP, null);
	private static final ScimGroupMember m7 = new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER);

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
