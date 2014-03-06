package org.cloudfoundry.identity.uaa.codestore;

import org.junit.Test;

import java.sql.Timestamp;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ExpiringCodeTests {
     @Test
     public void testIsExpired() throws Exception {
         ExpiringCode expiringCode = new ExpiringCode();
         assertFalse(expiringCode.isExpired());

         expiringCode.setExpiresAt(new Timestamp(System.currentTimeMillis() - 1000));
         assertTrue(expiringCode.isExpired());

         expiringCode.setExpiresAt(new Timestamp(System.currentTimeMillis() + 1000));
         assertFalse(expiringCode.isExpired());
     }
 }
