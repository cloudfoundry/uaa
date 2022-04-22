package org.cloudfoundry.identity.uaa.audit;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.util.List;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PrincipalAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;
import static org.junit.jupiter.api.Assertions.assertEquals;

@WithDatabaseContext
class JdbcAuditServiceTests {

    private JdbcAuditService auditService;

    private String authDetails;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void createService() {
        auditService = new JdbcAuditService(jdbcTemplate);
        jdbcTemplate.execute("DELETE FROM sec_audit WHERE principal_id='1' or principal_id='clientA' or principal_id='clientB'");
        authDetails = "1.1.1.1";
    }

    @Test
    void userAuthenticationFailureAuditSucceeds() throws Exception {
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        Thread.sleep(100);
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        List<AuditEvent> events = auditService.find("1", 0, IdentityZone.getUaaZoneId());
        assertEquals(2, events.size());
        assertEquals("1", events.get(0).getPrincipalId());
        assertEquals("joe", events.get(0).getData());
        assertEquals("1.1.1.1", events.get(0).getOrigin());
        assertEquals(IdentityZone.getUaaZoneId(), events.get(0).getIdentityZoneId());
    }

    @Test
    void principalAuthenticationFailureAuditSucceeds() {
        auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientA"), getAuditEvent(PrincipalAuthenticationFailure, "clientA").getIdentityZoneId());
        List<AuditEvent> events = auditService.find("clientA", 0, IdentityZone.getUaaZoneId());
        assertEquals(1, events.size());
        assertEquals("clientA", events.get(0).getPrincipalId());
        assertEquals("1.1.1.1", events.get(0).getOrigin());
        assertEquals(IdentityZone.getUaaZoneId(), events.get(0).getIdentityZoneId());
    }

    @Test
    void findMethodOnlyReturnsEventsWithinRequestedPeriod() {
        long now = System.currentTimeMillis();
        auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientA"), getAuditEvent(PrincipalAuthenticationFailure, "clientA").getIdentityZoneId());
        // Set the created column to one hour past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 3600 * 1000));
        auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientA"), getAuditEvent(PrincipalAuthenticationFailure, "clientA").getIdentityZoneId());
        auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientB"), getAuditEvent(PrincipalAuthenticationFailure, "clientB").getIdentityZoneId());
        // Find events within last 2 mins
        List<AuditEvent> events = auditService.find("clientA", now - 120 * 1000, IdentityZone.getUaaZoneId());
        assertEquals(1, events.size());
    }

    private AuditEvent getAuditEvent(AuditEventType type, String principal) {
        return getAuditEvent(type, principal, null);
    }

    private AuditEvent getAuditEvent(AuditEventType type, String principal, String data) {
        return new AuditEvent(type, principal, authDetails, data, System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
    }

}
