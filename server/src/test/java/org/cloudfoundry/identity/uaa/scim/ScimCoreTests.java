
package org.cloudfoundry.identity.uaa.scim;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import java.util.Date;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Test;

public class ScimCoreTests {

    @Test
    public void testEquals() {
        ScimCore c1 = new ScimUser("c1", "c1", null, null);
        ScimCore c2 = new ScimGroup("c1", null, IdentityZoneHolder.get().getId());
        ScimCore c3 = new ScimUser();
        ScimCore c4 = new ScimGroup();

        assertEquals(c1, c2);
        assertNotSame(c1, c3);
        assertNotSame(c2, c4);
        assertNotSame(c3, c4);
        assertTrue(c2.equals("c1"));
        assertFalse(c1.equals("c2"));
    }

    @Test
    public void testPatch() {
        ScimCore c1 = new ScimGroup("Test");
        ScimCore c2 = new ScimGroup();
        ScimMeta meta1 = c1.getMeta();
        ScimMeta meta2 = c2.getMeta();
        Date meta2Timestamp = meta2.getCreated();
        meta1.setCreated(new Date());
        meta1.setVersion(0);
        meta2.setVersion(1);
        meta2.setAttributes(new String[]{"Description"});
        c2.patch(c1);
        assertEquals(meta2Timestamp, c2.getMeta().getCreated());
        assertEquals(1, meta2.getVersion());
        assertEquals(1, meta2.getAttributes().length);
        assertEquals("Description", meta2.getAttributes()[0]);
    }
}
