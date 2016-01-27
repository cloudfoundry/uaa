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

import java.sql.Timestamp;
import java.util.List;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PasswordChangeSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationSuccess;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;

public class JdbcFailedLoginCountingAuditServiceTests extends JdbcTestBase {

    private JdbcFailedLoginCountingAuditService auditService;

    private String authDetails;

    @Before
    public void createService() throws Exception {
        auditService = new JdbcFailedLoginCountingAuditService(dataSource);
        jdbcTemplate.execute("DELETE FROM sec_audit WHERE principal_id='1' or principal_id='clientA' or principal_id='clientB'");
        authDetails = "1.1.1.1";
    }

    @Test
    public void userAuthenticationFailureAuditSucceeds() throws Exception {
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        Thread.sleep(100);
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        List<AuditEvent> events = auditService.find("1", 0);
        assertEquals(2, events.size());
        assertEquals("1", events.get(0).getPrincipalId());
        assertEquals("joe", events.get(0).getData());
        assertEquals("1.1.1.1", events.get(0).getOrigin());
    }

    @Test
    public void userAuthenticationFailureDeletesOldData() throws Exception {
        long now = System.currentTimeMillis();
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
        // Set the created column to 3 hours past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 3 * 3600 * 1000));
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
    }

    @Test
    public void userAuthenticationSuccessResetsData() throws Exception {
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
        auditService.log(getAuditEvent(UserAuthenticationSuccess, "1", "joe"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(0));
    }

    @Test
    public void userPasswordChangeSuccessResetsData() throws Exception {
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
        auditService.log(getAuditEvent(PasswordChangeSuccess, "1", "joe"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(0));
    }

    @Test
    public void findMethodOnlyReturnsEventsWithinRequestedPeriod() {
        long now = System.currentTimeMillis();
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        // Set the created column to one hour past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 3600 * 1000));
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        auditService.log(getAuditEvent(UserAuthenticationFailure, "2", "joe"));
        // Find events within last 2 mins
        List<AuditEvent> events = auditService.find("1", now - 120 * 1000);
        assertEquals(1, events.size());
    }

    private AuditEvent getAuditEvent(AuditEventType type, String principal, String data) {
        return new AuditEvent(type, principal, authDetails, data, System.currentTimeMillis(), IdentityZone.getUaa().getId());
    }

}
