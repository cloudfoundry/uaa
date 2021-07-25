package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.junit.Assert;
import org.junit.Test;

public class ApprovalModifiedEventTest {

    @Test(expected = IllegalArgumentException.class)
    public void testRaisesWithBadSource() {
        new ApprovalModifiedEvent(new Object(), new MockAuthentication());
    }

    @Test
    public void testAuditEvent() {
        Approval approval = new Approval()
            .setUserId("mruser")
            .setClientId("app")
            .setScope("cloud_controller.read")
            .setExpiresAt(Approval.timeFromNow(1000))
            .setStatus(Approval.ApprovalStatus.APPROVED);

        ApprovalModifiedEvent event = new ApprovalModifiedEvent(approval, null);

        AuditEvent auditEvent = event.getAuditEvent();
        Assert.assertEquals("{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}", auditEvent.getData());
        Assert.assertEquals(AuditEventType.ApprovalModifiedEvent, auditEvent.getType());
    }
}
