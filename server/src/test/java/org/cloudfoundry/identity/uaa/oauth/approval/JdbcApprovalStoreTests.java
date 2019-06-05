package org.cloudfoundry.identity.uaa.oauth.approval;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.test.*;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
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
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class JdbcApprovalStoreTests extends JdbcTestBase {

    private JdbcApprovalStore jdbcApprovalStore;

    private TestApplicationEventPublisher<ApprovalModifiedEvent> eventPublisher;

    private IdentityZone otherZone;

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

    @Before
    public void setUp() throws Exception {
        super.setUp();

        IdentityZoneHolder.clear();
        otherZone = MultitenancyFixture.identityZone("other-zone", "other-domain");
        for (String userId : Arrays.asList("u1", "u2", "u3")) {
            testAccounts.addRandomUser(jdbcTemplate, userId);
        }

        jdbcApprovalStore = spy(new JdbcApprovalStore(jdbcTemplate));

        eventPublisher = TestApplicationEventPublisher.forEventClass(ApprovalModifiedEvent.class);
        jdbcApprovalStore.setApplicationEventPublisher(eventPublisher);

        addApproval(jdbcTemplate, jdbcApprovalStore, "u1", "c1", "uaa.user", 6000, APPROVED, UAA);
        addApproval(jdbcTemplate, jdbcApprovalStore, "u1", "c2", "uaa.admin", 12000, DENIED, UAA);
        addApproval(jdbcTemplate, jdbcApprovalStore, "u2", "c1", "openid", 6000, APPROVED, UAA);
    }

    @Test
    public void deleteZoneDeletesApprovals() {
        String zoneId = IdentityZoneHolder.getUaaZone().getId();
        assertEquals(3, countZoneApprovals(jdbcTemplate, zoneId));
        jdbcApprovalStore.deleteByIdentityZone(zoneId);
        assertEquals(0, countZoneApprovals(jdbcTemplate, zoneId));
    }

    @Test
    public void deleteOtherZone() {
        String zoneId = otherZone.getId();
        String uaaZoneID = IdentityZoneHolder.getUaaZone().getId();

        assertEquals(0, countZoneApprovals(jdbcTemplate, zoneId));
        assertEquals(3, countZoneApprovals(jdbcTemplate, uaaZoneID));
        jdbcApprovalStore.deleteByIdentityZone(zoneId);
        assertEquals(0, countZoneApprovals(jdbcTemplate, zoneId));
        assertEquals(3, countZoneApprovals(jdbcTemplate, uaaZoneID));
    }

    @Test
    public void deleteProviderDeletesApprovals() {
        addApproval(jdbcTemplate, jdbcApprovalStore, "u4", "c1", "openid", 6000, APPROVED, LDAP);
        String zoneId = IdentityZoneHolder.getUaaZone().getId();
        assertEquals(4, countZoneApprovals(jdbcTemplate, zoneId));
        jdbcApprovalStore.deleteByOrigin(UAA, zoneId);
        assertEquals(1, countZoneApprovals(jdbcTemplate, zoneId));
    }

    @Test
    public void deleteOtherProvider() {
        addApproval(jdbcTemplate, jdbcApprovalStore, "u4", "c1", "openid", 6000, APPROVED, LDAP);
        String zoneId = otherZone.getId();
        String uaaZoneID = IdentityZoneHolder.getUaaZone().getId();

        assertEquals(0, countZoneApprovals(jdbcTemplate, zoneId));
        assertEquals(4, countZoneApprovals(jdbcTemplate, uaaZoneID));
        jdbcApprovalStore.deleteByOrigin(LDAP, zoneId);
        assertEquals(0, countZoneApprovals(jdbcTemplate, zoneId));
        assertEquals(4, countZoneApprovals(jdbcTemplate, uaaZoneID));
    }

    @Test
    public void deleteClient() {
        String zoneId = IdentityZoneHolder.getUaaZone().getId();
        String otherZoneId = otherZone.getId();
        assertEquals(2, countClientApprovals(jdbcTemplate, "c1", zoneId));
        assertEquals(0, countClientApprovals(jdbcTemplate, "c1", otherZoneId));
        jdbcApprovalStore.deleteByClient("c1", otherZoneId);
        assertEquals(2, countClientApprovals(jdbcTemplate, "c1", zoneId));
        assertEquals(0, countClientApprovals(jdbcTemplate, "c1", otherZoneId));
        jdbcApprovalStore.deleteByClient("c1", zoneId);
        assertEquals(0, countClientApprovals(jdbcTemplate, "c1", zoneId));
        assertEquals(0, countClientApprovals(jdbcTemplate, "c1", otherZoneId));
    }

    @Test
    public void deleteUser() {
        String zoneId = IdentityZoneHolder.getUaaZone().getId();
        String otherZoneId = otherZone.getId();
        assertEquals(2, countUserApprovals(jdbcTemplate, "u1", zoneId));
        assertEquals(0, countUserApprovals(jdbcTemplate, "u1", otherZoneId));
        jdbcApprovalStore.deleteByUser("u1", otherZoneId);
        assertEquals(2, countUserApprovals(jdbcTemplate, "u1", zoneId));
        assertEquals(0, countUserApprovals(jdbcTemplate, "u1", otherZoneId));
        jdbcApprovalStore.deleteByUser("u1", zoneId);
        assertEquals(0, countUserApprovals(jdbcTemplate, "u1", zoneId));
        assertEquals(0, countUserApprovals(jdbcTemplate, "u1", otherZoneId));
    }

    @Test
    public void addAndGetApproval() {
        String userId = "user";
        String clientId = "client";
        String scope = "uaa.user";
        long expiresIn = 1000L;
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
        jdbcApprovalStore.addApproval(newApproval, IdentityZoneHolder.get().getId());
        List<Approval> approvals = jdbcApprovalStore.getApprovals(userId, clientId, IdentityZoneHolder.get().getId());

        assertEquals(clientId, approvals.get(0).getClientId());
        assertEquals(userId, approvals.get(0).getUserId());
        //time comparison - we're satisfied if it is within 2 seconds
        assertThat((int) Math.abs(expiresAt.getTime() / 1000d - approvals.get(0).getExpiresAt().getTime() / 1000d), lessThan(2));
        assertThat((int) Math.abs(lastUpdatedAt.getTime() / 1000d - approvals.get(0).getLastUpdatedAt().getTime() / 1000d), lessThan(2));
        assertEquals(scope, approvals.get(0).getScope());
        assertEquals(status, approvals.get(0).getStatus());
    }

    @Test
    public void canGetApprovals() {
        assertEquals(2, jdbcApprovalStore.getApprovalsForClient("c1", IdentityZoneHolder.get().getId()).size());
        assertEquals(1, jdbcApprovalStore.getApprovals("u2", "c1", IdentityZoneHolder.get().getId()).size());
        assertEquals(0, jdbcApprovalStore.getApprovals("u2", "c2", IdentityZoneHolder.get().getId()).size());
        assertEquals(1, jdbcApprovalStore.getApprovals("u1", "c1", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canAddApproval() {
        assertTrue(jdbcApprovalStore.addApproval(new Approval()
                .setUserId("u2")
                .setClientId("c2")
                .setScope("dash.user")
                .setExpiresAt(Approval.timeFromNow(12000))
                .setStatus(APPROVED), IdentityZoneHolder.get().getId()));
        List<Approval> apps = jdbcApprovalStore.getApprovals("u2", "c2", IdentityZoneHolder.get().getId());
        assertEquals(1, apps.size());
        Approval app = apps.iterator().next();
        assertEquals("dash.user", app.getScope());
        assertTrue(app.getExpiresAt().after(new Date()));
        assertEquals(APPROVED, app.getStatus());
    }

    @Test
    public void approvalsIsZoneAware() {
        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", IdentityZoneHolder.get().getId()).size(), equalTo(2));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c2", IdentityZoneHolder.get().getId()).size(), equalTo(1));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", IdentityZoneHolder.get().getId()).size(), equalTo(0));

        IdentityZoneHolder.set(otherZone);
        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", IdentityZoneHolder.get().getId()).size(), equalTo(0));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c2", IdentityZoneHolder.get().getId()).size(), equalTo(0));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", IdentityZoneHolder.get().getId()).size(), equalTo(0));
        jdbcApprovalStore.revokeApprovalsForClient("c1", IdentityZoneHolder.get().getId());
        jdbcApprovalStore.revokeApprovalsForClient("c2", IdentityZoneHolder.get().getId());
        jdbcApprovalStore.revokeApprovalsForClient("c3", IdentityZoneHolder.get().getId());
        jdbcApprovalStore.revokeApprovalsForUser("u1", IdentityZoneHolder.get().getId());
        jdbcApprovalStore.revokeApprovalsForUser("u2", IdentityZoneHolder.get().getId());
        jdbcApprovalStore.revokeApprovalsForUser("u3", IdentityZoneHolder.get().getId());

        IdentityZoneHolder.clear();
        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", IdentityZoneHolder.get().getId()).size(), equalTo(2));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c2", IdentityZoneHolder.get().getId()).size(), equalTo(1));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", IdentityZoneHolder.get().getId()).size(), equalTo(0));
    }

    @Test
    public void canRevokeApprovals() {
        assertEquals(2, jdbcApprovalStore.getApprovalsForUser("u1", IdentityZoneHolder.get().getId()).size());
        assertTrue(jdbcApprovalStore.revokeApprovalsForUser("u1", IdentityZoneHolder.get().getId()));
        assertEquals(0, jdbcApprovalStore.getApprovalsForUser("u1", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRevokeSingleApproval() {
        List<Approval> approvals = jdbcApprovalStore.getApprovalsForUser("u1", IdentityZoneHolder.get().getId());
        assertEquals(2, approvals.size());

        Approval toRevoke = approvals.get(0);
        assertTrue(jdbcApprovalStore.revokeApproval(toRevoke, IdentityZoneHolder.get().getId()));
        List<Approval> approvalsAfterRevoke = jdbcApprovalStore.getApprovalsForUser("u1", IdentityZoneHolder.get().getId());

        assertEquals(1, approvalsAfterRevoke.size());
        assertFalse(approvalsAfterRevoke.contains(toRevoke));
    }

    @Test
    public void addSameApprovalRepeatedlyUpdatesExpiry() {
        Date timeFromNow = Approval.timeFromNow(6000);
        assertTrue(jdbcApprovalStore.addApproval(new Approval()
                .setUserId("u2")
                .setClientId("c2")
                .setScope("dash.user")
                .setExpiresAt(timeFromNow)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId()));
        Approval app = jdbcApprovalStore.getApprovals("u2", "c2", IdentityZoneHolder.get().getId()).iterator().next();
        //time comparison - we're satisfied if it is within 2 seconds
        assertThat((int) Math.abs(timeFromNow.getTime() / 1000d - app.getExpiresAt().getTime() / 1000d), lessThan(2));


        timeFromNow = Approval.timeFromNow(8000);
        assertTrue(jdbcApprovalStore.addApproval(new Approval()
                .setUserId("u2")
                .setClientId("c2")
                .setScope("dash.user")
                .setExpiresAt(timeFromNow)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId()));
        app = jdbcApprovalStore.getApprovals("u2", "c2", IdentityZoneHolder.get().getId()).iterator().next();
        assertThat((int) Math.abs(timeFromNow.getTime() / 1000d - app.getExpiresAt().getTime() / 1000d), lessThan(2));
    }

    @Test
    public void refreshApprovalCallsGetZoneId() {
        Approval app = jdbcApprovalStore.getApprovals("u1", "c1", IdentityZoneHolder.get().getId()).iterator().next();
        IdentityZone spy = spy(IdentityZoneHolder.get());
        IdentityZoneHolder.set(spy);
        jdbcApprovalStore.refreshApproval(app, IdentityZoneHolder.get().getId());
        verify(spy, times(1)).getId();
    }

    @Test
    public void canRefreshApproval() {
        Approval app = jdbcApprovalStore.getApprovals("u1", "c1", IdentityZoneHolder.get().getId()).iterator().next();
        Date now = new Date();

        jdbcApprovalStore.refreshApproval(new Approval()
                .setUserId(app.getUserId())
                .setClientId(app.getClientId())
                .setScope(app.getScope())
                .setExpiresAt(now)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        app = jdbcApprovalStore.getApprovals("u1", "c1", IdentityZoneHolder.get().getId()).iterator().next();
        assertThat((int) Math.abs(now.getTime() / 1000d - app.getExpiresAt().getTime() / 1000d), lessThan(2));
    }

    @Test
    public void canPurgeExpiredApprovals() throws InterruptedException {
        assertEquals(0, jdbcApprovalStore.getApprovalsForClient("c3", IdentityZoneHolder.get().getId()).size());
        assertEquals(0, jdbcApprovalStore.getApprovalsForUser("u3", IdentityZoneHolder.get().getId()).size());
        assertEquals(2, jdbcApprovalStore.getApprovalsForClient("c1", IdentityZoneHolder.get().getId()).size());
        assertEquals(2, jdbcApprovalStore.getApprovalsForUser("u1", IdentityZoneHolder.get().getId()).size());
        addApproval(jdbcTemplate, jdbcApprovalStore, "u3", "c3", "test1", 0, APPROVED, UAA);
        addApproval(jdbcTemplate, jdbcApprovalStore, "u3", "c3", "test2", 0, DENIED, UAA);
        addApproval(jdbcTemplate, jdbcApprovalStore, "u3", "c3", "test3", 0, APPROVED, UAA);
        assertEquals(3, jdbcApprovalStore.getApprovalsForClient("c3", IdentityZoneHolder.get().getId()).size());
        assertEquals(3, jdbcApprovalStore.getApprovalsForUser("u3", IdentityZoneHolder.get().getId()).size());

        // On mysql, the expiry is rounded off to the nearest second so
        // the following assert could randomly fail.
        Thread.sleep(1500);
        jdbcApprovalStore.purgeExpiredApprovals();
        assertEquals(0, jdbcApprovalStore.getApprovalsForClient("c3", IdentityZoneHolder.get().getId()).size());
        assertEquals(0, jdbcApprovalStore.getApprovalsForUser("u3", IdentityZoneHolder.get().getId()).size());
        assertEquals(2, jdbcApprovalStore.getApprovalsForClient("c1", IdentityZoneHolder.get().getId()).size());
        assertEquals(2, jdbcApprovalStore.getApprovalsForUser("u1", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void addingAndUpdatingAnApprovalPublishesEvents() {
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

        jdbcApprovalStore.addApproval(approval, IdentityZoneHolder.get().getId());

        Assert.assertEquals(1, eventPublisher.getEventCount());

        ApprovalModifiedEvent addEvent = eventPublisher.getLatestEvent();
        Assert.assertEquals(approval, addEvent.getSource());
        Assert.assertEquals(authentication, addEvent.getAuthentication());
        Assert.assertEquals("{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}", addEvent.getAuditEvent().getData());

        approval.setStatus(DENIED);

        eventPublisher.clearEvents();
        jdbcApprovalStore.addApproval(approval, IdentityZoneHolder.get().getId());

        Assert.assertEquals(1, eventPublisher.getEventCount());

        ApprovalModifiedEvent modifyEvent = eventPublisher.getLatestEvent();
        Assert.assertEquals(approval, modifyEvent.getSource());
        Assert.assertEquals(authentication, modifyEvent.getAuthentication());
        Assert.assertEquals("{\"scope\":\"cloud_controller.read\",\"status\":\"DENIED\"}", addEvent.getAuditEvent().getData());
    }

    private static void addApproval(
            final JdbcTemplate jdbcTemplate,
            final JdbcApprovalStore jdbcApprovalStore,
            final String userId,
            final String clientId,
            final String scope,
            final long expiresIn,
            final ApprovalStatus status,
            final String origin) {
        String sql = "insert into users (id, username, password, email, origin) values (?,?,?,?,?)";
        try {
            jdbcTemplate.update(sql, userId, userId, userId, userId + "@testapprovals.com", origin);
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
        jdbcApprovalStore.addApproval(newApproval, IdentityZoneHolder.get().getId());
    }

    private static int countClientApprovals(
            final JdbcTemplate jdbcTemplate,
            final String clientId,
            final String zoneId) {
        return jdbcTemplate.queryForObject("select count(*) from authz_approvals where client_id=? and identity_zone_id = ?", new Object[]{clientId, zoneId}, Integer.class);
    }

    private static int countUserApprovals(
            final JdbcTemplate jdbcTemplate,
            final String userId,
            final String zoneId) {
        return jdbcTemplate.queryForObject("select count(*) from authz_approvals where user_id=? and identity_zone_id = ?", new Object[]{userId, zoneId}, Integer.class);
    }

    private static int countZoneApprovals(
            final JdbcTemplate jdbcTemplate,
            final String zoneId) {
        return jdbcTemplate.queryForObject("select count(*) from authz_approvals where identity_zone_id = ?", new Object[]{zoneId}, Integer.class);
    }

}
