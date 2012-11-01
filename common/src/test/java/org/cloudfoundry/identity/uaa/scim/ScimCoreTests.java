package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.scim.core.ScimCore;
import org.cloudfoundry.identity.uaa.scim.groups.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.users.ScimUser;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class ScimCoreTests {

	@Test
	public void testEquals() {
		ScimCore c1 = new ScimUser("c1", "c1", null, null);
		ScimCore c2 = new ScimGroup("c1", null);
		ScimCore c3 = new ScimUser();
		ScimCore c4 = new ScimGroup();

		assertEquals(c1, c2);
		assertNotSame(c1, c3);
		assertNotSame(c2, c4);
		assertNotSame(c3, c4);
		assertTrue(c2.equals("c1"));
		assertFalse(c1.equals("c2"));
	}
}
