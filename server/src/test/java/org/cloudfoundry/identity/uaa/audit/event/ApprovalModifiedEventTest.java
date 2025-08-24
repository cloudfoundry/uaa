package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class ApprovalModifiedEventTest {

    @Test
    void raisesWithBadSource() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new ApprovalModifiedEvent(new Object(), new MockAuthentication()));
    }

    @Test
    void auditEvent() {
        Approval approval = new Approval()
                .setUserId("mruser")
                .setClientId("app")
                .setScope("cloud_controller.read")
                .setExpiresAt(Approval.timeFromNow(1000))
                .setStatus(Approval.ApprovalStatus.APPROVED);

        ApprovalModifiedEvent event = new ApprovalModifiedEvent(approval, null);

        AuditEvent auditEvent = event.getAuditEvent();
        assertThat(auditEvent.getData()).isEqualTo("{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}");
        assertThat(auditEvent.getType()).isEqualTo(AuditEventType.ApprovalModifiedEvent);
    }
}
