package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class UaaLoginHintTest {

    @Test
    public void testParseHintNull() {
        assertNull(UaaLoginHint.parseRequestParameter(null));
    }

    @Test
    public void testParseHintOrigin() {
        UaaLoginHint hint = UaaLoginHint.parseRequestParameter("{\"origin\":\"ldap\"}");
        assertNotNull(hint);
        assertEquals("ldap", hint.getOrigin());
    }
}
