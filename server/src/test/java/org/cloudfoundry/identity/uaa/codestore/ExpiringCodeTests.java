
package org.cloudfoundry.identity.uaa.codestore;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.sql.Timestamp;

import org.junit.Test;

public class ExpiringCodeTests {
    @Test
    public void testIsExpired() {
        ExpiringCode expiringCode = new ExpiringCode();
        assertFalse(expiringCode.isExpired());

        expiringCode.setExpiresAt(new Timestamp(System.currentTimeMillis() - 1000));
        assertTrue(expiringCode.isExpired());

        expiringCode.setExpiresAt(new Timestamp(System.currentTimeMillis() + 1000));
        assertFalse(expiringCode.isExpired());
    }
}
