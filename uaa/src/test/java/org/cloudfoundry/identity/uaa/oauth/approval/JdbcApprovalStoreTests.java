package org.cloudfoundry.identity.uaa.oauth.approval;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.jupiter.api.Assertions.*;

@WithDatabaseContext
class JdbcApprovalStoreTests {

    private JdbcApprovalStore jdbcApprovalStore;

    private TestApplicationEventPublisher<ApprovalModifiedEvent> eventPublisher;

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private String defaultZoneId;
    private String otherZoneId;
    private RandomValueStringGenerator generator;

    @BeforeEach
    void setUp() {
        generator = new RandomValueStringGenerator();
        defaultZoneId = "defaultZoneId-" + generator.generate();
        otherZoneId = "otherZoneId-" + generator.generate();

        Stream.of("u1", "u2", "u3").forEach(
                userId -> testAccounts.addUser(jdbcTemplate, userId, defaultZoneId)
        );

        jdbcApprovalStore = new JdbcApprovalStore(jdbcTemplate);

        eventPublisher = TestApplicationEventPublisher.forEventClass(ApprovalModifiedEvent.class);
        jdbcApprovalStore.setApplicationEventPublisher(eventPublisher);

        addApproval(jdbcApprovalStore, "u1", "c1", "uaa.user", 6000, APPROVED, defaultZoneId);
        addApproval(jdbcApprovalStore, "u1", "c2", "uaa.admin", 12000, DENIED, defaultZoneId);
        addApproval(jdbcApprovalStore, "u2", "c1", "openid", 6000, APPROVED, defaultZoneId);
    }

    @AfterEach
    void tearDown() {
        jdbcTemplate.execute("delete from users");
        jdbcTemplate.execute("delete from authz_approvals");
    }

    @Test
    void deleteZoneDeletesApprovals() {
        assertEquals(3, countZoneApprovals(jdbcTemplate, defaultZoneId));
        jdbcApprovalStore.deleteByIdentityZone(defaultZoneId);
        assertEquals(0, countZoneApprovals(jdbcTemplate, defaultZoneId));
    }

    @Test
    void deleteOtherZone() {
        assertEquals(0, countZoneApprovals(jdbcTemplate, otherZoneId));
        assertEquals(3, countZoneApprovals(jdbcTemplate, defaultZoneId));
        jdbcApprovalStore.deleteByIdentityZone(otherZoneId);
        assertEquals(0, countZoneApprovals(jdbcTemplate, otherZoneId));
        assertEquals(3, countZoneApprovals(jdbcTemplate, defaultZoneId));
    }

    @Test
    void deleteProviderDeletesApprovals() {
        final String zoneId = "zoneId-" + generator.generate();
        final String origin = "origin-" + generator.generate();
        final String userId = "userId-" + generator.generate();

        testAccounts.addUser(jdbcTemplate, userId, zoneId, origin);
        addApproval(jdbcApprovalStore, userId, "c1", "openid", 6000, APPROVED, zoneId);

        jdbcApprovalStore.deleteByOrigin(origin, zoneId);

        Integer actual = jdbcTemplate.queryForObject(
                "select count(*) from authz_approvals where user_id = ?",
                Integer.class,
                userId);
        assertEquals(new Integer(0), actual);
    }

    @Test
    void deleteOtherProvider() {
        addApproval(jdbcApprovalStore, "u4", "c1", "openid", 6000, APPROVED, defaultZoneId);

        assertEquals(0, countZoneApprovals(jdbcTemplate, otherZoneId));
        assertEquals(4, countZoneApprovals(jdbcTemplate, defaultZoneId));
        jdbcApprovalStore.deleteByOrigin(LDAP, otherZoneId);
        assertEquals(0, countZoneApprovals(jdbcTemplate, otherZoneId));
        assertEquals(4, countZoneApprovals(jdbcTemplate, defaultZoneId));
    }

    @Test
    void deleteClient() {
        assertEquals(2, countClientApprovals(jdbcTemplate, "c1", defaultZoneId));
        assertEquals(0, countClientApprovals(jdbcTemplate, "c1", otherZoneId));
        jdbcApprovalStore.deleteByClient("c1", otherZoneId);
        assertEquals(2, countClientApprovals(jdbcTemplate, "c1", defaultZoneId));
        assertEquals(0, countClientApprovals(jdbcTemplate, "c1", otherZoneId));
        jdbcApprovalStore.deleteByClient("c1", defaultZoneId);
        assertEquals(0, countClientApprovals(jdbcTemplate, "c1", defaultZoneId));
        assertEquals(0, countClientApprovals(jdbcTemplate, "c1", otherZoneId));
    }

    @Test
    void deleteUser() {
        assertEquals(2, countUserApprovals(jdbcTemplate, "u1", defaultZoneId));
        assertEquals(0, countUserApprovals(jdbcTemplate, "u1", otherZoneId));
        jdbcApprovalStore.deleteByUser("u1", otherZoneId);
        assertEquals(2, countUserApprovals(jdbcTemplate, "u1", defaultZoneId));
        assertEquals(0, countUserApprovals(jdbcTemplate, "u1", otherZoneId));
        jdbcApprovalStore.deleteByUser("u1", defaultZoneId);
        assertEquals(0, countUserApprovals(jdbcTemplate, "u1", defaultZoneId));
        assertEquals(0, countUserApprovals(jdbcTemplate, "u1", otherZoneId));
    }

    @Test
    void addAndGetApproval() {
        String userId = "user";
        String clientId = "client";
        String scope = "uaa.user";
        long expiresIn = 1000L;
        Date lastUpdatedAt = new Date();
        ApprovalStatus status = APPROVED;
        testAccounts.addUser(jdbcTemplate, userId, IdentityZoneHolder.get().getId());

        Date expiresAt = new Timestamp(new Date().getTime() + expiresIn);
        Approval newApproval = new Approval()
                .setUserId(userId)
                .setClientId(clientId)
                .setScope(scope)
                .setExpiresAt(expiresAt)
                .setStatus(status)
                .setLastUpdatedAt(lastUpdatedAt);
        jdbcApprovalStore.addApproval(newApproval, defaultZoneId);
        List<Approval> approvals = jdbcApprovalStore.getApprovals(userId, clientId, defaultZoneId);

        assertEquals(clientId, approvals.get(0).getClientId());
        assertEquals(userId, approvals.get(0).getUserId());
        //time comparison - we're satisfied if it is within 2 seconds
        assertThat((int) Math.abs(expiresAt.getTime() / 1000d - approvals.get(0).getExpiresAt().getTime() / 1000d), lessThan(2));
        assertThat((int) Math.abs(lastUpdatedAt.getTime() / 1000d - approvals.get(0).getLastUpdatedAt().getTime() / 1000d), lessThan(2));
        assertEquals(scope, approvals.get(0).getScope());
        assertEquals(status, approvals.get(0).getStatus());
    }

    @Test
    void canGetApprovals() {
        assertEquals(2, jdbcApprovalStore.getApprovalsForClient("c1", defaultZoneId).size());
        assertEquals(1, jdbcApprovalStore.getApprovals("u2", "c1", defaultZoneId).size());
        assertEquals(0, jdbcApprovalStore.getApprovals("u2", "c2", defaultZoneId).size());
        assertEquals(1, jdbcApprovalStore.getApprovals("u1", "c1", defaultZoneId).size());
    }

    @Test
    void canAddApproval() {
        assertTrue(jdbcApprovalStore.addApproval(new Approval()
                .setUserId("u2")
                .setClientId("c2")
                .setScope("dash.user")
                .setExpiresAt(Approval.timeFromNow(12000))
                .setStatus(APPROVED), defaultZoneId));
        List<Approval> apps = jdbcApprovalStore.getApprovals("u2", "c2", defaultZoneId);
        assertEquals(1, apps.size());
        Approval app = apps.iterator().next();
        assertEquals("dash.user", app.getScope());
        assertTrue(app.getExpiresAt().after(new Date()));
        assertEquals(APPROVED, app.getStatus());
    }

    @Test
    void approvalsIsZoneAware() {
        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", defaultZoneId).size(), equalTo(2));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c2", defaultZoneId).size(), equalTo(1));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", defaultZoneId).size(), equalTo(0));

        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", otherZoneId).size(), equalTo(0));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c2", otherZoneId).size(), equalTo(0));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", otherZoneId).size(), equalTo(0));
        jdbcApprovalStore.revokeApprovalsForClient("c1", otherZoneId);
        jdbcApprovalStore.revokeApprovalsForClient("c2", otherZoneId);
        jdbcApprovalStore.revokeApprovalsForClient("c3", otherZoneId);
        jdbcApprovalStore.revokeApprovalsForUser("u1", otherZoneId);
        jdbcApprovalStore.revokeApprovalsForUser("u2", otherZoneId);
        jdbcApprovalStore.revokeApprovalsForUser("u3", otherZoneId);

        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", defaultZoneId).size(), equalTo(2));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c2", defaultZoneId).size(), equalTo(1));
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", defaultZoneId).size(), equalTo(0));
    }

    @Test
    void canRevokeApprovals() {
        assertEquals(2, jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId).size());
        assertTrue(jdbcApprovalStore.revokeApprovalsForUser("u1", defaultZoneId));
        assertEquals(0, jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId).size());
    }

    @Test
    void canRevokeSingleApproval() {
        List<Approval> approvals = jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId);
        assertEquals(2, approvals.size());

        Approval toRevoke = approvals.get(0);
        assertTrue(jdbcApprovalStore.revokeApproval(toRevoke, defaultZoneId));
        List<Approval> approvalsAfterRevoke = jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId);

        assertEquals(1, approvalsAfterRevoke.size());
        assertFalse(approvalsAfterRevoke.contains(toRevoke));
    }

    @Test
    void addSameApprovalRepeatedlyUpdatesExpiry() {
        Date timeFromNow = Approval.timeFromNow(6000);
        assertTrue(jdbcApprovalStore.addApproval(new Approval()
                .setUserId("u2")
                .setClientId("c2")
                .setScope("dash.user")
                .setExpiresAt(timeFromNow)
                .setStatus(APPROVED), defaultZoneId));
        Approval app = jdbcApprovalStore.getApprovals("u2", "c2", defaultZoneId).iterator().next();
        //time comparison - we're satisfied if it is within 2 seconds
        assertThat((int) Math.abs(timeFromNow.getTime() / 1000d - app.getExpiresAt().getTime() / 1000d), lessThan(2));


        timeFromNow = Approval.timeFromNow(8000);
        assertTrue(jdbcApprovalStore.addApproval(new Approval()
                .setUserId("u2")
                .setClientId("c2")
                .setScope("dash.user")
                .setExpiresAt(timeFromNow)
                .setStatus(APPROVED), defaultZoneId));
        app = jdbcApprovalStore.getApprovals("u2", "c2", defaultZoneId).iterator().next();
        assertThat((int) Math.abs(timeFromNow.getTime() / 1000d - app.getExpiresAt().getTime() / 1000d), lessThan(2));
    }

    // TODO: Understand this test. Do we need this test?
//    @Test
//    void refreshApprovalCallsGetZoneId() {
//        Approval app = jdbcApprovalStore.getApprovals("u1", "c1", defaultZoneId).iterator().next();
//        IdentityZone spy = spy(IdentityZoneHolder.get());
//        IdentityZoneHolder.set(spy);
//        jdbcApprovalStore.refreshApproval(app, defaultZoneId);
//        verify(spy, times(1)).getId();
//    }

    @Test
    void canRefreshApproval() {
        Approval app = jdbcApprovalStore.getApprovals("u1", "c1", defaultZoneId).iterator().next();
        Date now = new Date();

        jdbcApprovalStore.refreshApproval(new Approval()
                .setUserId(app.getUserId())
                .setClientId(app.getClientId())
                .setScope(app.getScope())
                .setExpiresAt(now)
                .setStatus(APPROVED), defaultZoneId);
        app = jdbcApprovalStore.getApprovals("u1", "c1", defaultZoneId).iterator().next();
        assertThat((int) Math.abs(now.getTime() / 1000d - app.getExpiresAt().getTime() / 1000d), lessThan(2));
    }

    @Test
    void canPurgeExpiredApprovals() throws InterruptedException {
        assertEquals(0, jdbcApprovalStore.getApprovalsForClient("c3", defaultZoneId).size());
        assertEquals(0, jdbcApprovalStore.getApprovalsForUser("u3", defaultZoneId).size());
        assertEquals(2, jdbcApprovalStore.getApprovalsForClient("c1", defaultZoneId).size());
        assertEquals(2, jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId).size());
        addApproval(jdbcApprovalStore, "u3", "c3", "test1", 0, APPROVED, defaultZoneId);
        addApproval(jdbcApprovalStore, "u3", "c3", "test2", 0, DENIED, defaultZoneId);
        addApproval(jdbcApprovalStore, "u3", "c3", "test3", 0, APPROVED, defaultZoneId);
        assertEquals(3, jdbcApprovalStore.getApprovalsForClient("c3", defaultZoneId).size());
        assertEquals(3, jdbcApprovalStore.getApprovalsForUser("u3", defaultZoneId).size());

        // On mysql, the expiry is rounded off to the nearest second so
        // the following assert could randomly fail.
        Thread.sleep(1500);
        jdbcApprovalStore.purgeExpiredApprovals();
        assertEquals(0, jdbcApprovalStore.getApprovalsForClient("c3", defaultZoneId).size());
        assertEquals(0, jdbcApprovalStore.getApprovalsForUser("u3", defaultZoneId).size());
        assertEquals(2, jdbcApprovalStore.getApprovalsForClient("c1", defaultZoneId).size());
        assertEquals(2, jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId).size());
    }

    @Test
    void addingAndUpdatingAnApprovalPublishesEvents() {
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

        jdbcApprovalStore.addApproval(approval, defaultZoneId);

        assertEquals(1, eventPublisher.getEventCount());

        ApprovalModifiedEvent addEvent = eventPublisher.getLatestEvent();
        assertEquals(approval, addEvent.getSource());
        assertEquals(authentication, addEvent.getAuthentication());
        assertEquals("{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}", addEvent.getAuditEvent().getData());

        approval.setStatus(DENIED);

        eventPublisher.clearEvents();
        jdbcApprovalStore.addApproval(approval, defaultZoneId);

        assertEquals(1, eventPublisher.getEventCount());

        ApprovalModifiedEvent modifyEvent = eventPublisher.getLatestEvent();
        assertEquals(approval, modifyEvent.getSource());
        assertEquals(authentication, modifyEvent.getAuthentication());
        assertEquals("{\"scope\":\"cloud_controller.read\",\"status\":\"DENIED\"}", addEvent.getAuditEvent().getData());
    }

    private static void addApproval(
            final JdbcApprovalStore jdbcApprovalStore,
            final String userId,
            final String clientId,
            final String scope,
            final long expiresIn,
            final ApprovalStatus status,
            final String zoneId) {
        Date expiresAt = new Timestamp(new Date().getTime() + expiresIn);
        Date lastUpdatedAt = new Date();
        Approval newApproval = new Approval()
                .setUserId(userId)
                .setClientId(clientId)
                .setScope(scope)
                .setExpiresAt(expiresAt)
                .setStatus(status)
                .setLastUpdatedAt(lastUpdatedAt);
        jdbcApprovalStore.addApproval(newApproval, zoneId);
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
