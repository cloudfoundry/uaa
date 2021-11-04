package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class ApprovalModifiedEventTest {

    @Test
    void testRaisesWithBadSource() {
        assertThrows(IllegalArgumentException.class, () -> new ApprovalModifiedEvent(new Object(), new MockAuthentication()));
    }

    @Test
    void testAuditEvent() {
        Approval approval = new Approval()
            .setUserId("mruser")
            .setClientId("app")
            .setScope("cloud_controller.read")
            .setExpiresAt(Approval.timeFromNow(1000))
            .setStatus(Approval.ApprovalStatus.APPROVED);

        ApprovalModifiedEvent event = new ApprovalModifiedEvent(approval, null);

        AuditEvent auditEvent = event.getAuditEvent();
        assertEquals("{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}", auditEvent.getData());
        assertEquals(AuditEventType.ApprovalModifiedEvent, auditEvent.getType());
    }
}
