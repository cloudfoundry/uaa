/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.audit;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;

import java.sql.Timestamp;
import java.util.List;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PrincipalAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;
import static org.junit.Assert.assertEquals;
public class JdbcAuditServiceTests extends JdbcTestBase {

    private JdbcAuditService auditService;

    private String authDetails;

    @Before
    public void createService() throws Exception {
        auditService = new JdbcAuditService(jdbcTemplate);
        jdbcTemplate.execute("DELETE FROM sec_audit WHERE principal_id='1' or principal_id='clientA' or principal_id='clientB'");
        authDetails = "1.1.1.1";
    }

    @Test
    public void userAuthenticationFailureAuditSucceeds() throws Exception {
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        Thread.sleep(100);
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        List<AuditEvent> events = auditService.find("1", 0, IdentityZoneHolder.get().getId());
        assertEquals(2, events.size());
        assertEquals("1", events.get(0).getPrincipalId());
        assertEquals("joe", events.get(0).getData());
        assertEquals("1.1.1.1", events.get(0).getOrigin());
        assertEquals(IdentityZone.getUaaZoneId(), events.get(0).getIdentityZoneId());
    }

    @Test
    public void principalAuthenticationFailureAuditSucceeds() {
        auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientA"), getAuditEvent(PrincipalAuthenticationFailure, "clientA").getIdentityZoneId());
        List<AuditEvent> events = auditService.find("clientA", 0, IdentityZoneHolder.get().getId());
        assertEquals(1, events.size());
        assertEquals("clientA", events.get(0).getPrincipalId());
        assertEquals("1.1.1.1", events.get(0).getOrigin());
        assertEquals(IdentityZone.getUaaZoneId(), events.get(0).getIdentityZoneId());
    }

    @Test
    public void findMethodOnlyReturnsEventsWithinRequestedPeriod() throws Exception {
        long now = System.currentTimeMillis();
        auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientA"), getAuditEvent(PrincipalAuthenticationFailure, "clientA").getIdentityZoneId());
        // Set the created column to one hour past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 3600 * 1000));
        auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientA"), getAuditEvent(PrincipalAuthenticationFailure, "clientA").getIdentityZoneId());
        auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientB"), getAuditEvent(PrincipalAuthenticationFailure, "clientB").getIdentityZoneId());
        // Find events within last 2 mins
        List<AuditEvent> events = auditService.find("clientA", now - 120 * 1000, IdentityZoneHolder.get().getId());
        assertEquals(1, events.size());
    }

    private AuditEvent getAuditEvent(AuditEventType type, String principal) {
        return getAuditEvent(type, principal, null);
    }

    private AuditEvent getAuditEvent(AuditEventType type, String principal, String data) {
        return new AuditEvent(type, principal, authDetails, data, System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
    }

}
