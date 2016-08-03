package org.cloudfoundry.identity.uaa.audit;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AuditEventTypeTests {
    
    @Test
    public void testAuditEventType() {
        int count = 0;
        for (AuditEventType type : AuditEventType.values()) {
            assertEquals(count, type.getCode());
            assertEquals(type, AuditEventType.fromCode(count));
            count++;
        }
    }
}
