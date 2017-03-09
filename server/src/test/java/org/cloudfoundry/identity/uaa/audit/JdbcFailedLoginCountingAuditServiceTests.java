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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.util.Collections;
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
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verifyZeroInteractions;

@RunWith(Parameterized.class)
public class JdbcFailedLoginCountingAuditServiceTests extends JdbcTestBase {

    private JdbcFailedLoginCountingAuditService auditService;

    private String authDetails;
    private boolean clientEnabled;
    private JdbcTemplate template;

    @Parameterized.Parameters
    public static Object[][] getParameters() {
        return new Object[][]{{true}, {false}};
    }

    public JdbcFailedLoginCountingAuditServiceTests(boolean clientEnabled) {
        this.clientEnabled = clientEnabled;
    }


    @Before
    public void createService() throws Exception {
        template = spy(jdbcTemplate);
        auditService = new JdbcFailedLoginCountingAuditService(template, this.clientEnabled);
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
        // Set the created column to 25 hours past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 25 * 3600 * 1000));
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
        assertEquals(clientEnabled ? 1 : 0, clientEvents.size());
    }

    @Test
    public void clientAuthenticationFailureAuditSucceeds() throws Exception {
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        Thread.sleep(100);
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        List<AuditEvent> events = clientEnabled ? auditService.find("client", 0) : Collections.emptyList();
        assertEquals(clientEnabled ? 2 : 0, events.size());
        if (clientEnabled) {
            assertEquals("client", events.get(0).getPrincipalId());
            assertEquals("testman", events.get(0).getData());
            assertEquals("1.1.1.1", events.get(0).getOrigin());
        } else {
            verifyZeroInteractions(template);
        }
    }

    @Test
    public void clientAuthenticationFailureDeletesOldData() throws Exception {
        long now = System.currentTimeMillis();
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(clientEnabled ? 1 : 0));
        // Set the created column to 25 hours past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 25 * 3600 * 1000));
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(clientEnabled ? 1 : 0));
        if (!clientEnabled) {
            verifyZeroInteractions(template);
        }
    }

    @Test
    public void clientAuthenticationSuccessResetsData() throws Exception {
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(clientEnabled ? 1 : 0));
        auditService.log(getAuditEvent(ClientAuthenticationSuccess, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(0));
        if (!clientEnabled) {
            verifyZeroInteractions(template);
        }
    }

    @Test
    public void clientSecretChangeSuccessResetsData() throws Exception {
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(clientEnabled ? 1 : 0));
        auditService.log(getAuditEvent(SecretChangeSuccess, "client", "testman"));
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='client'", Integer.class), is(0));
        if (!clientEnabled) {
            verifyZeroInteractions(template);
        }
    }

    private AuditEvent getAuditEvent(AuditEventType type, String principal, String data) {
        return new AuditEvent(type, principal, authDetails, data, System.currentTimeMillis(), IdentityZone.getUaa().getId());
    }

}
