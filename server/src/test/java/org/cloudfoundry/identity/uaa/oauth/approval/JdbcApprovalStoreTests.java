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

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.context.SecurityContextHolder;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.spy;

public class JdbcApprovalStoreTests extends JdbcTestBase {


    private JdbcApprovalStore dao;

    private TestApplicationEventPublisher<ApprovalModifiedEvent> eventPublisher;

    private IdentityZone otherZone;

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

    @Before
    public void initJdbcApprovalStoreTests() {
        IdentityZoneHolder.clear();
        otherZone = MultitenancyFixture.identityZone("other-zone", "other-domain");
        for (String userId : Arrays.asList("u1", "u2", "u3")) {
            testAccounts.addRandomUser(jdbcTemplate, userId);
        }

        dao = spy(new JdbcApprovalStore(jdbcTemplate));

        eventPublisher = TestApplicationEventPublisher.forEventClass(ApprovalModifiedEvent.class);
        dao.setApplicationEventPublisher(eventPublisher);

        addApproval("u1", "c1", "uaa.user", 6000, APPROVED, UAA);
        addApproval("u1", "c2", "uaa.admin", 12000, DENIED, UAA);
        addApproval("u2", "c1", "openid", 6000, APPROVED, UAA);
    }

    private void addApproval(String userId, String clientId, String scope, long expiresIn, ApprovalStatus status, String origin) {
        String zoneId = IdentityZoneHolder.get().getId();
        String sql = "insert into users (id, username, password, email, origin) values (?,?,?,?,?)";
        try {
            jdbcTemplate.update(sql, userId, userId, userId, userId+"@testapprovals.com", origin);
        } catch (DataIntegrityViolationException e) {
            //ignore, user exists
        }
        Date expiresAt = new Timestamp(new Date().getTime() + expiresIn);
        Date lastUpdatedAt = new Date();
        Approval newApproval = new Approval()
            .setUserId(userId)
            .setClientId(clientId)
            .setScope(scope)
            .setExpiresAt(expiresAt)
            .setStatus(status)
            .setLastUpdatedAt(lastUpdatedAt);
        dao.addApproval(newApproval);
    }

    public int countClientApprovals(String clientId, String zoneId) {
        return jdbcTemplate.queryForObject("select count(*) from authz_approvals where client_id=? and identity_zone_id = ?", new Object[] {clientId, zoneId}, Integer.class);
    }

    public int countUserApprovals(String userId, String zoneId) {
        return jdbcTemplate.queryForObject("select count(*) from authz_approvals where user_id=? and identity_zone_id = ?", new Object[] {userId, zoneId}, Integer.class);
    }

    public int countZoneApprovals(String zoneId) {
        return jdbcTemplate.queryForObject("select count(*) from authz_approvals where identity_zone_id = ?", new Object[] {zoneId}, Integer.class);
    }

    @After
    public void cleanupDataSource() throws Exception {
        TestUtils.deleteFrom(dataSource, "authz_approvals");
        assertThat(jdbcTemplate.queryForObject("select count(*) from authz_approvals", Integer.class), is(0));
        IdentityZoneHolder.clear();
    }

    @Test
    public void delete_zone_deletes_approvals() throws Exception {
        String zoneId = IdentityZoneHolder.getUaaZone().getId();
        assertEquals(3, countZoneApprovals(zoneId));
        dao.deleteByIdentityZone(zoneId);
        assertEquals(0, countZoneApprovals(zoneId));
    }

    @Test
    public void delete_other_zone() throws Exception {
        String zoneId = otherZone.getId();
        String uaaZoneID = IdentityZoneHolder.getUaaZone().getId();;
        assertEquals(0, countZoneApprovals(zoneId));
        assertEquals(3, countZoneApprovals(uaaZoneID));
        dao.deleteByIdentityZone(zoneId);
        assertEquals(0, countZoneApprovals(zoneId));
        assertEquals(3, countZoneApprovals(uaaZoneID));
    }

    @Test
    public void delete_provider_deletes_approvals() throws Exception {
        addApproval("u4", "c1", "openid", 6000, APPROVED, LDAP);
        String zoneId = IdentityZoneHolder.getUaaZone().getId();
        assertEquals(4, countZoneApprovals(zoneId));
        dao.deleteByOrigin(UAA, zoneId);
        assertEquals(1, countZoneApprovals(zoneId));
    }

    @Test
    public void delete_other_provider() throws Exception {
        addApproval("u4", "c1", "openid", 6000, APPROVED, LDAP);
        String zoneId = otherZone.getId();
        String uaaZoneID = IdentityZoneHolder.getUaaZone().getId();;
        assertEquals(0, countZoneApprovals(zoneId));
        assertEquals(4, countZoneApprovals(uaaZoneID));
        dao.deleteByOrigin(LDAP, zoneId);
        assertEquals(0, countZoneApprovals(zoneId));
        assertEquals(4, countZoneApprovals(uaaZoneID));
    }

    @Test
    public void delete_client() throws Exception {
        String zoneId = IdentityZoneHolder.getUaaZone().getId();
        String otherZoneId = otherZone.getId();
        assertEquals(2, countClientApprovals("c1", zoneId));
        assertEquals(0, countClientApprovals("c1", otherZoneId));
        dao.deleteByClient("c1", otherZoneId);
        assertEquals(2, countClientApprovals("c1", zoneId));
        assertEquals(0, countClientApprovals("c1", otherZoneId));
        dao.deleteByClient("c1", zoneId);
        assertEquals(0, countClientApprovals("c1", zoneId));
        assertEquals(0, countClientApprovals("c1", otherZoneId));
    }

    @Test
    public void delete_user() throws Exception {
        String zoneId = IdentityZoneHolder.getUaaZone().getId();
        String otherZoneId = otherZone.getId();
        assertEquals(2, countUserApprovals("u1", zoneId));
        assertEquals(0, countUserApprovals("u1", otherZoneId));
        dao.deleteByUser("u1", otherZoneId);
        assertEquals(2, countUserApprovals("u1", zoneId));
        assertEquals(0, countUserApprovals("u1", otherZoneId));
        dao.deleteByUser("u1", zoneId);
        assertEquals(0, countUserApprovals("u1", zoneId));
        assertEquals(0, countUserApprovals("u1", otherZoneId));
    }

    @Test
    public void testAddAndGetApproval() {
        String userId = "user";
        String clientId = "client";
        String scope = "uaa.user";
        long expiresIn = 1000l;
        Date lastUpdatedAt = new Date();
        ApprovalStatus status = APPROVED;
        testAccounts.addRandomUser(jdbcTemplate, userId);

        Date expiresAt = new Timestamp(new Date().getTime() + expiresIn);
        Approval newApproval = new Approval()
            .setUserId(userId)
            .setClientId(clientId)
            .setScope(scope)
            .setExpiresAt(expiresAt)
            .setStatus(status)
            .setLastUpdatedAt(lastUpdatedAt);
        dao.addApproval(newApproval);
        List<Approval> approvals = dao.getApprovals(userId, clientId);

        assertEquals(clientId, approvals.get(0).getClientId());
        assertEquals(userId, approvals.get(0).getUserId());
        //time comparison - we're satisfied if it is within 2 seconds
        assertThat((int)Math.abs(expiresAt.getTime()/1000d - approvals.get(0).getExpiresAt().getTime()/1000d), lessThan(2));
        assertThat((int)Math.abs(lastUpdatedAt.getTime()/1000d - approvals.get(0).getLastUpdatedAt().getTime()/1000d), lessThan(2));
        assertEquals(scope, approvals.get(0).getScope());
        assertEquals(status, approvals.get(0).getStatus());
    }

    @Test
    public void canGetApprovals() {
        assertEquals(2, dao.getApprovalsForClient("c1").size());
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
    public void approvals_is_zone_aware() throws Exception {
        String filter = "client_id eq \"c1\" or client_id eq \"c2\" or client_id eq \"c3\"";
        assertThat(dao.getApprovalsForClient("c1").size(), equalTo(2));
        assertThat(dao.getApprovalsForClient("c2").size(), equalTo(1));
        assertThat(dao.getApprovalsForClient("c3").size(), equalTo(0));

        IdentityZoneHolder.set(otherZone);
        assertThat(dao.getApprovalsForClient("c1").size(), equalTo(0));
        assertThat(dao.getApprovalsForClient("c2").size(), equalTo(0));
        assertThat(dao.getApprovalsForClient("c3").size(), equalTo(0));
        dao.revokeApprovalsForClient("c1");
        dao.revokeApprovalsForClient("c2");
        dao.revokeApprovalsForClient("c3");
        dao.revokeApprovalsForUser("u1");
        dao.revokeApprovalsForUser("u2");
        dao.revokeApprovalsForUser("u3");

        IdentityZoneHolder.clear();
        assertThat(dao.getApprovalsForClient("c1").size(), equalTo(2));
        assertThat(dao.getApprovalsForClient("c2").size(), equalTo(1));
        assertThat(dao.getApprovalsForClient("c3").size(), equalTo(0));
    }

    @Test
    public void canRevokeApprovals() {
        assertEquals(2, dao.getApprovalsForUser("u1").size());
        assertTrue(dao.revokeApprovalsForUser("u1"));
        assertEquals(0, dao.getApprovalsForUser("u1").size());
    }

    @Test
    public void canRevokeSingleApproval() {
        List<Approval> approvals = dao.getApprovalsForUser("u1");
        assertEquals(2, approvals.size());

        Approval toRevoke = approvals.get(0);
        assertTrue(dao.revokeApproval(toRevoke));
        List<Approval> approvalsAfterRevoke = dao.getApprovalsForUser("u1");

        assertEquals(1, approvalsAfterRevoke.size());
        assertFalse(approvalsAfterRevoke.contains(toRevoke));
    }

    @Test
    public void addSameApprovalRepeatedlyUpdatesExpiry() {
        Date timeFromNow = Approval.timeFromNow(6000);
        assertTrue(dao.addApproval(new Approval()
            .setUserId("u2")
            .setClientId("c2")
            .setScope("dash.user")
            .setExpiresAt(timeFromNow)
            .setStatus(APPROVED)));
        Approval app = dao.getApprovals("u2", "c2").iterator().next();
        //time comparison - we're satisfied if it is within 2 seconds
        assertThat((int)Math.abs(timeFromNow.getTime()/1000d - app.getExpiresAt().getTime()/1000d), lessThan(2));


        timeFromNow = Approval.timeFromNow(8000);
        assertTrue(dao.addApproval(new Approval()
            .setUserId("u2")
            .setClientId("c2")
            .setScope("dash.user")
            .setExpiresAt(timeFromNow)
            .setStatus(APPROVED)));
        app = dao.getApprovals("u2", "c2").iterator().next();
        assertThat((int)Math.abs(timeFromNow.getTime()/1000d - app.getExpiresAt().getTime()/1000d), lessThan(2));
    }

    @Test
    @Ignore //this test has issues
    public void addSameApprovalDifferentStatusRepeatedlyOnlyUpdatesStatus() {
        Date timeFromNow = Approval.timeFromNow(6000);
        assertTrue(dao.addApproval(new Approval()
            .setUserId("u2")
            .setClientId("c2")
            .setScope("dash.user")
            .setExpiresAt(timeFromNow)
            .setStatus(APPROVED)));
        Approval app = dao.getApprovals("u2", "c2").iterator().next();
        assertThat((int)Math.abs(timeFromNow.getTime()/1000d - app.getExpiresAt().getTime()/1000d), lessThan(2));

        timeFromNow = Approval.timeFromNow(8000);
        assertTrue(dao.addApproval(new Approval()
            .setUserId("u2")
            .setClientId("c2")
            .setScope("dash.user")
            .setExpiresAt(timeFromNow)
            .setStatus(DENIED)));
        app = dao.getApprovals("u2", "c2").iterator().next();
        assertThat((int)Math.abs(timeFromNow.getTime()/1000d - app.getExpiresAt().getTime()/1000d), lessThan(2));
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
        assertThat((int)Math.abs(now.getTime()/1000d - app.getExpiresAt().getTime()/1000d), lessThan(2));
    }

    @Test
    public void canPurgeExpiredApprovals() throws InterruptedException {
        assertEquals(0, dao.getApprovalsForClient("c3").size());
        assertEquals(0, dao.getApprovalsForUser("u3").size());
        assertEquals(2, dao.getApprovalsForClient("c1").size());
        assertEquals(2, dao.getApprovalsForUser("u1").size());
        addApproval("u3", "c3", "test1", 0, APPROVED, UAA);
        addApproval("u3", "c3", "test2", 0, DENIED, UAA);
        addApproval("u3", "c3", "test3", 0, APPROVED, UAA);
        assertEquals(3, dao.getApprovalsForClient("c3").size());
        assertEquals(3, dao.getApprovalsForUser("u3").size());

        // On mysql, the expiry is rounded off to the nearest second so
        // the following assert could randomly fail.
        Thread.sleep(1500);
        dao.purgeExpiredApprovals();
        assertEquals(0, dao.getApprovalsForClient("c3").size());
        assertEquals(0, dao.getApprovalsForUser("u3").size());
        assertEquals(2, dao.getApprovalsForClient("c1").size());
        assertEquals(2, dao.getApprovalsForUser("u1").size());
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
