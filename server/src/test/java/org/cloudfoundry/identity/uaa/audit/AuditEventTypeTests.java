package org.cloudfoundry.identity.uaa.audit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuditEventTypeTests {
    
    @Test
    void testAuditEventType() {
        int count = 0;
        for (AuditEventType type : AuditEventType.values()) {
            assertEquals(count, type.getCode());
            assertEquals(type, AuditEventType.fromCode(count));
            count++;
        }
    }
}
