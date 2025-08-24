package org.cloudfoundry.identity.uaa.audit;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuditEventTypeTests {

    @Test
    void auditEventType() {
        int count = 0;
        for (AuditEventType type : AuditEventType.values()) {
            assertThat(type.getCode()).isEqualTo(count);
            assertThat(AuditEventType.fromCode(count)).isEqualTo(type);
            count++;
        }
    }
}
