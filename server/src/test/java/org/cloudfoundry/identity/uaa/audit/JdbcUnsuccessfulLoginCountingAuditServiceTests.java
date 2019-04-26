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
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.Timestamp;
import java.util.EnumSet;
import java.util.List;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.ClientAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.MfaAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.MfaAuthenticationSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PasswordChangeSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAccountUnlockedEvent;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationSuccess;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.collection.IsEmptyCollection.empty;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class JdbcUnsuccessfulLoginCountingAuditServiceTests extends JdbcTestBase {

    private JdbcUnsuccessfulLoginCountingAuditService auditService;

    private String authDetails;
    private JdbcTemplate template;

    @Before
    public void createService() throws Exception {
        template = spy(jdbcTemplate);
        auditService = new JdbcUnsuccessfulLoginCountingAuditService(template);
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
    }

    @Test
    public void userAuthenticationFailureDeletesOldData() throws Exception {
        long now = System.currentTimeMillis();
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
        ReflectionTestUtils.invokeMethod(ReflectionTestUtils.getField(auditService, "lastDelete"), "set", 0l);
        // Set the created column to 25 hours past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 25 * 3600 * 1000));
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
    }

    @Test
    public void delete_happens_single_thread_on_intervals() throws Exception {
        long now = System.currentTimeMillis();
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
        // Set the created column to 25 hours past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 25 * 3600 * 1000));
        int count = 5;
        for (int i = 0; i< count; i++) {
            auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
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
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
        auditService.log(getAuditEvent(UserAuthenticationSuccess, "1", "joe"), getAuditEvent(UserAuthenticationSuccess, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(0));
    }

    @Test
    public void userPasswordChangeSuccessResetsData() throws Exception {
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
        auditService.log(getAuditEvent(PasswordChangeSuccess, "1", "joe"), getAuditEvent(PasswordChangeSuccess, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(0));
    }

    @Test
    public void findMethodOnlyReturnsEventsWithinRequestedPeriod() {
        long now = System.currentTimeMillis();
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"), getAuditEvent(ClientAuthenticationFailure, "client", "testman").getIdentityZoneId());
        // Set the created column to 2 hour past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 3600 * 1000));
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        auditService.log(getAuditEvent(UserAuthenticationFailure, "2", "joe"), getAuditEvent(UserAuthenticationFailure, "2", "joe").getIdentityZoneId());
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"), getAuditEvent(ClientAuthenticationFailure, "client", "testman").getIdentityZoneId());
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "otherclient", "testman"), getAuditEvent(ClientAuthenticationFailure, "otherclient", "testman").getIdentityZoneId());
        // Find events within last 2 mins
        List<AuditEvent> userEvents = auditService.find("1", now - 120 * 1000, IdentityZoneHolder.get().getId());
        List<AuditEvent> clientEvents = auditService.find("client", now - 120 * 1000, IdentityZoneHolder.get().getId());
        assertEquals(1, userEvents.size());
        assertEquals(0, clientEvents.size());
    }

    @Test
    public void mfaFailedEventsAreLogged() {
        String principalId = "1";
        AuditEvent mfaFailureEvent = new AuditEvent(MfaAuthenticationFailure, principalId, authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(mfaFailureEvent, mfaFailureEvent.getIdentityZoneId());

        assertThat(auditService.find(principalId, 0, mfaFailureEvent.getIdentityZoneId()), is(hasSize(1)));
    }

    @Test
    public void mfaAuthenticationSuccessResetsData() {
        AuditEvent mfaFailureEvent = new AuditEvent(MfaAuthenticationFailure, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(mfaFailureEvent, mfaFailureEvent.getIdentityZoneId());

        AuditEvent mfaSuccessEvent = new AuditEvent(MfaAuthenticationSuccess, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(mfaSuccessEvent, mfaSuccessEvent.getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(0));
    }

    @Test
    public void mfaAuthenticationSuccessResetsOnlyMfaAuthenticationFailures() {
        AuditEvent mfaFailureEvent = new AuditEvent(MfaAuthenticationFailure, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(mfaFailureEvent, mfaFailureEvent.getIdentityZoneId());

        AuditEvent loginFailureEvent = new AuditEvent(UserAuthenticationFailure, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(loginFailureEvent, loginFailureEvent.getIdentityZoneId());

        AuditEvent mfaSuccessEvent = new AuditEvent(MfaAuthenticationSuccess, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(mfaSuccessEvent, mfaSuccessEvent.getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class), is(1));
    }

    @Test
    public void nontAuthSuccessesShouldNotThrowAnException() {
        EnumSet<AuditEventType> userAuthenticationSuccess = EnumSet.of(UserAuthenticationSuccess, PasswordChangeSuccess, UserAccountUnlockedEvent, MfaAuthenticationSuccess);
        EnumSet<AuditEventType> complementOfUserAuthenticationSuccess = EnumSet.complementOf(userAuthenticationSuccess);

        for (AuditEventType ofUserAuthenticationSuccess : complementOfUserAuthenticationSuccess) {
            AuditEvent auditEvent = new AuditEvent(ofUserAuthenticationSuccess, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
            auditService.log(auditEvent, "some zone");
        }
    }

    @Test
    public void userUnlockShouldResetBothUserandMfaAuthentication() {
        AuditEvent mfaFailureEvent = new AuditEvent(MfaAuthenticationFailure, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(mfaFailureEvent, mfaFailureEvent.getIdentityZoneId());

        AuditEvent loginFailureEvent = new AuditEvent(UserAuthenticationFailure, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(loginFailureEvent, loginFailureEvent.getIdentityZoneId());

        AuditEvent unlockEvent = new AuditEvent(UserAccountUnlockedEvent, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(unlockEvent, unlockEvent.getIdentityZoneId());

        assertThat(auditService.find("1", 0, mfaFailureEvent.getIdentityZoneId()), is(empty()));
    }

    private AuditEvent getAuditEvent(AuditEventType type, String principal, String data) {
        return new AuditEvent(type, principal, authDetails, data, System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
    }

}
