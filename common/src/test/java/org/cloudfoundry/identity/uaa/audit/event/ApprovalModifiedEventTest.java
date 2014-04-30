package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.junit.Assert;
import org.junit.Test;

public class ApprovalModifiedEventTest {

    @Test(expected = IllegalArgumentException.class)
    public void testRaisesWithBadSource() throws Exception {
        new ApprovalModifiedEvent(new Object(), new MockAuthentication());
    }

    @Test
    public void testAuditEvent() throws Exception {
        Approval approval = new Approval("mruser", "app", "cloud_controller.read", 1000, Approval.ApprovalStatus.APPROVED);

        ApprovalModifiedEvent event = new ApprovalModifiedEvent(approval, null);

        AuditEvent auditEvent = event.getAuditEvent();
        Assert.assertEquals("{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}", auditEvent.getData());
        Assert.assertEquals(AuditEventType.ApprovalModifiedEvent, auditEvent.getType());
    }
}