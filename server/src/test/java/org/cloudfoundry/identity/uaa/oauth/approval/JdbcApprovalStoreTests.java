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
package org.cloudfoundry.identity.uaa.oauth.approval;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.security.core.context.SecurityContextHolder;
@Ignore //we're having issues with these tests right now
public class JdbcApprovalStoreTests extends JdbcTestBase {
    private JdbcApprovalStore dao;

    private TestApplicationEventPublisher<ApprovalModifiedEvent> eventPublisher;

    @Before
    public void initJdbcApprovalStoreTests() {

        dao = new JdbcApprovalStore(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter),
                        new SimpleSearchQueryConverter());

        eventPublisher = TestApplicationEventPublisher.forEventClass(ApprovalModifiedEvent.class);
        dao.setApplicationEventPublisher(eventPublisher);

        addApproval("u1", "c1", "uaa.user", 6000, APPROVED);
        addApproval("u1", "c2", "uaa.admin", 12000, DENIED);
        addApproval("u2", "c1", "openid", 6000, APPROVED);
    }

    private void addApproval(String userName, String clientId, String scope, long expiresIn, ApprovalStatus status) {
        Date expiresAt = new Timestamp(new Date().getTime() + expiresIn);
        Date lastUpdatedAt = new Date();
        Approval newApproval = new Approval()
            .setUserId(userName)
            .setClientId(clientId)
            .setScope(scope)
            .setExpiresAt(expiresAt)
            .setStatus(status)
            .setLastUpdatedAt(lastUpdatedAt);
        dao.addApproval(newApproval);
    }

    @After
    public void cleanupDataSource() throws Exception {
        TestUtils.deleteFrom(dataSource, "authz_approvals");
        assertThat(jdbcTemplate.queryForObject("select count(*) from authz_approvals", Integer.class), is(0));
    }

    @Test
    public void testAddAndGetApproval() {
        String userName = "user";
        String clientId = "client";
        String scope = "uaa.user";
        long expiresIn = 1000l;
        Date lastUpdatedAt = new Date();
        ApprovalStatus status = APPROVED;

        Date expiresAt = new Timestamp(new Date().getTime() + expiresIn);
        Approval newApproval = new Approval()
            .setUserId(userName)
            .setClientId(clientId)
            .setScope(scope)
            .setExpiresAt(expiresAt)
            .setStatus(status)
            .setLastUpdatedAt(lastUpdatedAt);
        dao.addApproval(newApproval);
        List<Approval> approvals = dao.getApprovals(userName, clientId);

        assertEquals(clientId, approvals.get(0).getClientId());
        assertEquals(userName, approvals.get(0).getUserId());
        assertEquals(Math.round(expiresAt.getTime() / 1000), Math.round(approvals.get(0).getExpiresAt().getTime() / 1000));
        assertEquals(Math.round(lastUpdatedAt.getTime() / 1000),
                        Math.round(approvals.get(0).getLastUpdatedAt().getTime() / 1000));
        assertEquals(scope, approvals.get(0).getScope());
        assertEquals(status, approvals.get(0).getStatus());
    }

    @Test
    public void canGetApprovals() {
        assertEquals(3, dao.getApprovals("user_id pr").size());
        assertEquals(1, dao.getApprovals("u2", "c1").size());
        assertEquals(0, dao.getApprovals("u2", "c2").size());
        assertEquals(1, dao.getApprovals("u1", "c1").size());
    }

    @Test
    public void canAddApproval() {
        assertTrue(dao.addApproval(new Approval()
            .setUserId("u2")
            .setClientId("c2")
            .setScope("dash.user")
            .setExpiresAt(Approval.timeFromNow(12000))
            .setStatus(APPROVED)));
        List<Approval> apps = dao.getApprovals("u2", "c2");
        assertEquals(1, apps.size());
        Approval app = apps.iterator().next();
        assertEquals("dash.user", app.getScope());
        assertTrue(app.getExpiresAt().after(new Date()));
        assertEquals(APPROVED, app.getStatus());
    }

    @Test
    public void canRevokeApprovals() {
        assertEquals(2, dao.getApprovals("user_id eq \"u1\"").size());
        assertTrue(dao.revokeApprovals("user_id eq \"u1\""));
        assertEquals(0, dao.getApprovals("user_id eq \"u1\"").size());
    }

    @Test
    public void canRevokeSingleApproval() {
        List<Approval> approvals = dao.getApprovals("user_id eq \"u1\"");
        assertEquals(2, approvals.size());

        Approval toRevoke = approvals.get(0);
        assertTrue(dao.revokeApproval(toRevoke));
        List<Approval> approvalsAfterRevoke = dao.getApprovals("user_id eq \"u1\"");

        assertEquals(1, approvalsAfterRevoke.size());
        assertFalse(approvalsAfterRevoke.contains(toRevoke));
    }

    @Test
    public void addSameApprovalRepeatedlyUpdatesExpiry() {
        assertTrue(dao.addApproval(new Approval()
            .setUserId("u2")
            .setClientId("c2")
            .setScope("dash.user")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(APPROVED)));
        Approval app = dao.getApprovals("u2", "c2").iterator().next();
        assertEquals(Math.round(app.getExpiresAt().getTime() / 1000), Math.round((new Date().getTime() + 6000) / 1000));

        assertTrue(dao.addApproval(new Approval()
            .setUserId("u2")
            .setClientId("c2")
            .setScope("dash.user")
            .setExpiresAt(Approval.timeFromNow(8000))
            .setStatus(APPROVED)));
        app = dao.getApprovals("u2", "c2").iterator().next();
        assertEquals(Math.round(app.getExpiresAt().getTime() / 1000), Math.round((new Date().getTime() + 8000) / 1000));
    }

    @Test
    @Ignore //this test has issues
    public void addSameApprovalDifferentStatusRepeatedlyOnlyUpdatesStatus() {
        assertTrue(dao.addApproval(new Approval()
            .setUserId("u2")
            .setClientId("c2")
            .setScope("dash.user")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(APPROVED)));
        Approval app = dao.getApprovals("u2", "c2").iterator().next();
        assertEquals(Math.round(app.getExpiresAt().getTime() / 1000), Math.round((new Date().getTime() + 6000) / 1000));

        assertTrue(dao.addApproval(new Approval()
            .setUserId("u2")
            .setClientId("c2")
            .setScope("dash.user")
            .setExpiresAt(Approval.timeFromNow(8000))
            .setStatus(DENIED)));
        app = dao.getApprovals("u2", "c2").iterator().next();
        assertEquals(Math.round(app.getExpiresAt().getTime() / 1000), Math.round((new Date().getTime() + 6000) / 1000));
        assertEquals(DENIED, app.getStatus());
    }

    @Test
    public void canRefreshApproval() {
        Approval app = dao.getApprovals("u1", "c1").iterator().next();
        Date now = new Date();

        dao.refreshApproval(new Approval()
            .setUserId(app.getUserId())
            .setClientId(app.getClientId())
            .setScope(app.getScope())
            .setExpiresAt(now)
            .setStatus(APPROVED));
        app = dao.getApprovals("u1", "c1").iterator().next();
        assertEquals(Math.round(now.getTime() / 1000), Math.round(app.getExpiresAt().getTime() / 1000));
    }

    @Test
    public void canPurgeExpiredApprovals() throws InterruptedException {
        List<Approval> approvals = dao.getApprovals("user_id pr");
        assertEquals(3, approvals.size());
        addApproval("u3", "c3", "test1", 0, APPROVED);
        addApproval("u3", "c3", "test2", 0, DENIED);
        addApproval("u3", "c3", "test3", 0, APPROVED);
        List<Approval> newApprovals = dao.getApprovals("user_id pr");
        assertEquals(6, newApprovals.size());

        // On mysql, the expiry is rounded off to the nearest second so
        // the following assert could randomly fail.
        Thread.sleep(500);
        dao.purgeExpiredApprovals();
        List<Approval> remainingApprovals = dao.getApprovals("user_id pr");
        assertEquals(3, remainingApprovals.size());
    }

    @Test
    public void testAddingAndUpdatingAnApprovalPublishesEvents() throws Exception {
        UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

        Approval approval = new Approval()
            .setUserId(testAccounts.getUserName())
            .setClientId("app")
            .setScope("cloud_controller.read")
            .setExpiresAt(Approval.timeFromNow(1000))
            .setStatus(ApprovalStatus.APPROVED);

        eventPublisher.clearEvents();

        MockAuthentication authentication = new MockAuthentication();
        SecurityContextHolder.getContext().setAuthentication(authentication);

        dao.addApproval(approval);

        Assert.assertEquals(1, eventPublisher.getEventCount());

        ApprovalModifiedEvent addEvent = eventPublisher.getLatestEvent();
        Assert.assertEquals(approval, addEvent.getSource());
        Assert.assertEquals(authentication, addEvent.getAuthentication());
        Assert.assertEquals("{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}", addEvent.getAuditEvent().getData());

        approval.setStatus(DENIED);

        eventPublisher.clearEvents();
        dao.addApproval(approval);

        Assert.assertEquals(1, eventPublisher.getEventCount());

        ApprovalModifiedEvent modifyEvent = eventPublisher.getLatestEvent();
        Assert.assertEquals(approval, modifyEvent.getSource());
        Assert.assertEquals(authentication, modifyEvent.getAuthentication());
        Assert.assertEquals("{\"scope\":\"cloud_controller.read\",\"status\":\"DENIED\"}", addEvent.getAuditEvent().getData());
    }
}
