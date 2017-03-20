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
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.Timestamp;
import java.util.List;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.ClientAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.ClientAuthenticationSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PasswordChangeSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.SecretChangeSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationSuccess;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

public class JdbcFailedLoginCountingAuditServiceTests extends JdbcTestBase {

    private JdbcFailedLoginCountingAuditService auditService;

    private String authDetails;
    private JdbcTemplate template;

    @Before
    public void createService() throws Exception {
        template = spy(jdbcTemplate);
        auditService = new JdbcFailedLoginCountingAuditService(template);
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
        ReflectionTestUtils.invokeMethod(ReflectionTestUtils.getField(auditService, "lastDelete"), "set", 0l);
        // Set the created column to 25 hours past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 25 * 3600 * 1000));
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
    }

    @Test
    public void delete_happens_single_thread_on_intervals() throws Exception {
        long now = System.currentTimeMillis();
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
        // Set the created column to 25 hours past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 25 * 3600 * 1000));
        int count = 5;
        for (int i = 0; i< count; i++) {
            auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        }
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(count+1));
        ArgumentCaptor<String> queries = ArgumentCaptor.forClass(String.class);
        verify(template, times(1)).update(queries.capture(), any(Timestamp.class));
    }

    @Test
    public void periodic_delete_works() throws Exception {
        for (int i=0; i<5; i++) {
            auditService.periodicDelete();
        }
        verify(template, times(1)).update(anyString(), any(Timestamp.class));
        // 30 seconds has passed
        auditService.setTimeService(new TimeService() {
            @Override
            public long getCurrentTimeMillis() {
                return System.currentTimeMillis() + (31 * 1000);
            }
        });
        reset(template);
        for (int i=0; i<5; i++) {
            auditService.periodicDelete();
        }
        verify(template, times(1)).update(anyString(), any(Timestamp.class));
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
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        // Set the created column to 2 hour past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 3600 * 1000));
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
        auditService.log(getAuditEvent(UserAuthenticationFailure, "2", "joe"));
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "otherclient", "testman"));
        // Find events within last 2 mins
        List<AuditEvent> userEvents = auditService.find("1", now - 120 * 1000);
        List<AuditEvent> clientEvents = auditService.find("client", now - 120 * 1000);
        assertEquals(1, userEvents.size());
        assertEquals(0, clientEvents.size());
    }

    @Test
    public void clientAuthenticationFailureAuditSucceeds() throws Exception {
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        Thread.sleep(100);
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        verifyZeroInteractions(template);
    }


    @Test
    public void clientAuthenticationFailureDeletesOldData() throws Exception {
        long now = System.currentTimeMillis();
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(0));
        // Set the created column to 25 hours past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 25 * 3600 * 1000));
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(0));
        verifyZeroInteractions(template);
    }

    @Test
    public void clientAuthenticationSuccessResetsData() throws Exception {
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(0));
        auditService.log(getAuditEvent(ClientAuthenticationSuccess, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(0));
        verifyZeroInteractions(template);
    }

    @Test
    public void clientSecretChangeSuccessResetsData() throws Exception {
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(0));
        auditService.log(getAuditEvent(SecretChangeSuccess, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(0));
        verifyZeroInteractions(template);
    }

    private AuditEvent getAuditEvent(AuditEventType type, String principal, String data) {
        return new AuditEvent(type, principal, authDetails, data, System.currentTimeMillis(), IdentityZone.getUaa().getId());
    }

    private AuditEvent getAuditEventForAltZone(AuditEventType type, String principal, String data) {
        return new AuditEvent(type, principal, authDetails, data, System.currentTimeMillis(), "test-zone");
    }

}
