package org.cloudfoundry.identity.uaa.oauth.approval;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
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

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;

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
        assertThat(countZoneApprovals(jdbcTemplate, defaultZoneId)).isEqualTo(3);
        jdbcApprovalStore.deleteByIdentityZone(defaultZoneId);
        assertThat(countZoneApprovals(jdbcTemplate, defaultZoneId)).isZero();
    }

    @Test
    void deleteOtherZone() {
        assertThat(countZoneApprovals(jdbcTemplate, otherZoneId)).isZero();
        assertThat(countZoneApprovals(jdbcTemplate, defaultZoneId)).isEqualTo(3);
        jdbcApprovalStore.deleteByIdentityZone(otherZoneId);
        assertThat(countZoneApprovals(jdbcTemplate, otherZoneId)).isZero();
        assertThat(countZoneApprovals(jdbcTemplate, defaultZoneId)).isEqualTo(3);
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
        assertThat(actual).isEqualTo(Integer.valueOf(0));
    }

    @Test
    void deleteOtherProvider() {
        addApproval(jdbcApprovalStore, "u4", "c1", "openid", 6000, APPROVED, defaultZoneId);

        assertThat(countZoneApprovals(jdbcTemplate, otherZoneId)).isZero();
        assertThat(countZoneApprovals(jdbcTemplate, defaultZoneId)).isEqualTo(4);
        jdbcApprovalStore.deleteByOrigin(LDAP, otherZoneId);
        assertThat(countZoneApprovals(jdbcTemplate, otherZoneId)).isZero();
        assertThat(countZoneApprovals(jdbcTemplate, defaultZoneId)).isEqualTo(4);
    }

    @Test
    void deleteClient() {
        assertThat(countClientApprovals(jdbcTemplate, "c1", defaultZoneId)).isEqualTo(2);
        assertThat(countClientApprovals(jdbcTemplate, "c1", otherZoneId)).isZero();
        jdbcApprovalStore.deleteByClient("c1", otherZoneId);
        assertThat(countClientApprovals(jdbcTemplate, "c1", defaultZoneId)).isEqualTo(2);
        assertThat(countClientApprovals(jdbcTemplate, "c1", otherZoneId)).isZero();
        jdbcApprovalStore.deleteByClient("c1", defaultZoneId);
        assertThat(countClientApprovals(jdbcTemplate, "c1", defaultZoneId)).isZero();
        assertThat(countClientApprovals(jdbcTemplate, "c1", otherZoneId)).isZero();
    }

    @Test
    void deleteUser() {
        assertThat(countUserApprovals(jdbcTemplate, "u1", defaultZoneId)).isEqualTo(2);
        assertThat(countUserApprovals(jdbcTemplate, "u1", otherZoneId)).isZero();
        jdbcApprovalStore.deleteByUser("u1", otherZoneId);
        assertThat(countUserApprovals(jdbcTemplate, "u1", defaultZoneId)).isEqualTo(2);
        assertThat(countUserApprovals(jdbcTemplate, "u1", otherZoneId)).isZero();
        jdbcApprovalStore.deleteByUser("u1", defaultZoneId);
        assertThat(countUserApprovals(jdbcTemplate, "u1", defaultZoneId)).isZero();
        assertThat(countUserApprovals(jdbcTemplate, "u1", otherZoneId)).isZero();
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

        assertThat(approvals.getFirst().getClientId()).isEqualTo(clientId);
        assertThat(approvals.getFirst().getUserId()).isEqualTo(userId);
        //time comparison - we're satisfied if it is within 2 seconds
        assertThat((int) Math.abs(expiresAt.getTime() / 1000d - approvals.getFirst().getExpiresAt().getTime() / 1000d)).isLessThan(2);
        assertThat((int) Math.abs(lastUpdatedAt.getTime() / 1000d - approvals.getFirst().getLastUpdatedAt().getTime() / 1000d)).isLessThan(2);
        assertThat(approvals.getFirst().getScope()).isEqualTo(scope);
        assertThat(approvals.getFirst().getStatus()).isEqualTo(status);
    }

    @Test
    void canGetApprovals() {
        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", defaultZoneId)).hasSize(2);
        assertThat(jdbcApprovalStore.getApprovals("u2", "c1", defaultZoneId)).hasSize(1);
        assertThat(jdbcApprovalStore.getApprovals("u2", "c2", defaultZoneId)).isEmpty();
        assertThat(jdbcApprovalStore.getApprovals("u1", "c1", defaultZoneId)).hasSize(1);
    }

    @Test
    void canAddApproval() {
        assertThat(jdbcApprovalStore.addApproval(new Approval()
                .setUserId("u2")
                .setClientId("c2")
                .setScope("dash.user")
                .setExpiresAt(Approval.timeFromNow(12000))
                .setStatus(APPROVED), defaultZoneId)).isTrue();
        List<Approval> apps = jdbcApprovalStore.getApprovals("u2", "c2", defaultZoneId);
        assertThat(apps).hasSize(1);
        Approval app = apps.getFirst();
        assertThat(app.getScope()).isEqualTo("dash.user");
        assertThat(app.getExpiresAt().after(new Date())).isTrue();
        assertThat(app.getStatus()).isEqualTo(APPROVED);
    }

    @Test
    void approvalsIsZoneAware() {
        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", defaultZoneId)).hasSize(2);
        assertThat(jdbcApprovalStore.getApprovalsForClient("c2", defaultZoneId)).hasSize(1);
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", defaultZoneId)).isEmpty();

        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", otherZoneId)).isEmpty();
        assertThat(jdbcApprovalStore.getApprovalsForClient("c2", otherZoneId)).isEmpty();
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", otherZoneId)).isEmpty();
        jdbcApprovalStore.revokeApprovalsForClient("c1", otherZoneId);
        jdbcApprovalStore.revokeApprovalsForClient("c2", otherZoneId);
        jdbcApprovalStore.revokeApprovalsForClient("c3", otherZoneId);
        jdbcApprovalStore.revokeApprovalsForUser("u1", otherZoneId);
        jdbcApprovalStore.revokeApprovalsForUser("u2", otherZoneId);
        jdbcApprovalStore.revokeApprovalsForUser("u3", otherZoneId);

        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", defaultZoneId)).hasSize(2);
        assertThat(jdbcApprovalStore.getApprovalsForClient("c2", defaultZoneId)).hasSize(1);
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", defaultZoneId)).isEmpty();
    }

    @Test
    void canRevokeApprovals() {
        assertThat(jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId)).hasSize(2);
        assertThat(jdbcApprovalStore.revokeApprovalsForUser("u1", defaultZoneId)).isTrue();
        assertThat(jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId)).isEmpty();
    }

    @Test
    void canRevokeSingleApproval() {
        List<Approval> approvals = jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId);
        assertThat(approvals).hasSize(2);

        Approval toRevoke = approvals.getFirst();
        assertThat(jdbcApprovalStore.revokeApproval(toRevoke, defaultZoneId)).isTrue();
        List<Approval> approvalsAfterRevoke = jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId);

        assertThat(approvalsAfterRevoke)
                .hasSize(1)
                .doesNotContain(toRevoke);
    }

    @Test
    void addSameApprovalRepeatedlyUpdatesExpiry() {
        Date timeFromNow = Approval.timeFromNow(6000);
        assertThat(jdbcApprovalStore.addApproval(new Approval()
                .setUserId("u2")
                .setClientId("c2")
                .setScope("dash.user")
                .setExpiresAt(timeFromNow)
                .setStatus(APPROVED), defaultZoneId)).isTrue();
        Approval app = jdbcApprovalStore.getApprovals("u2", "c2", defaultZoneId).getFirst();
        //time comparison - we're satisfied if it is within 2 seconds
        assertThat((int) Math.abs(timeFromNow.getTime() / 1000d - app.getExpiresAt().getTime() / 1000d)).isLessThan(2);


        timeFromNow = Approval.timeFromNow(8000);
        assertThat(jdbcApprovalStore.addApproval(new Approval()
                .setUserId("u2")
                .setClientId("c2")
                .setScope("dash.user")
                .setExpiresAt(timeFromNow)
                .setStatus(APPROVED), defaultZoneId)).isTrue();
        app = jdbcApprovalStore.getApprovals("u2", "c2", defaultZoneId).getFirst();
        assertThat((int) Math.abs(timeFromNow.getTime() / 1000d - app.getExpiresAt().getTime() / 1000d)).isLessThan(2);
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
        Approval app = jdbcApprovalStore.getApprovals("u1", "c1", defaultZoneId).getFirst();
        Date now = new Date();

        jdbcApprovalStore.refreshApproval(new Approval()
                .setUserId(app.getUserId())
                .setClientId(app.getClientId())
                .setScope(app.getScope())
                .setExpiresAt(now)
                .setStatus(APPROVED), defaultZoneId);
        app = jdbcApprovalStore.getApprovals("u1", "c1", defaultZoneId).getFirst();
        assertThat((int) Math.abs(now.getTime() / 1000d - app.getExpiresAt().getTime() / 1000d)).isLessThan(2);
    }

    @Test
    void canPurgeExpiredApprovals() throws InterruptedException {
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", defaultZoneId)).isEmpty();
        assertThat(jdbcApprovalStore.getApprovalsForUser("u3", defaultZoneId)).isEmpty();
        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", defaultZoneId)).hasSize(2);
        assertThat(jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId)).hasSize(2);
        addApproval(jdbcApprovalStore, "u3", "c3", "test1", 0, APPROVED, defaultZoneId);
        addApproval(jdbcApprovalStore, "u3", "c3", "test2", 0, DENIED, defaultZoneId);
        addApproval(jdbcApprovalStore, "u3", "c3", "test3", 0, APPROVED, defaultZoneId);
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", defaultZoneId)).hasSize(3);
        assertThat(jdbcApprovalStore.getApprovalsForUser("u3", defaultZoneId)).hasSize(3);

        // On mysql, the expiry is rounded off to the nearest second so
        // the following assert could randomly fail.
        Thread.sleep(1500);
        jdbcApprovalStore.purgeExpiredApprovals();
        assertThat(jdbcApprovalStore.getApprovalsForClient("c3", defaultZoneId)).isEmpty();
        assertThat(jdbcApprovalStore.getApprovalsForUser("u3", defaultZoneId)).isEmpty();
        assertThat(jdbcApprovalStore.getApprovalsForClient("c1", defaultZoneId)).hasSize(2);
        assertThat(jdbcApprovalStore.getApprovalsForUser("u1", defaultZoneId)).hasSize(2);
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

        assertThat(eventPublisher.getEventCount()).isOne();

        ApprovalModifiedEvent addEvent = eventPublisher.getLatestEvent();
        assertThat(addEvent.getSource()).isEqualTo(approval);
        assertThat(addEvent.getAuthentication()).isEqualTo(authentication);
        assertThat(addEvent.getAuditEvent().getData()).isEqualTo("{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}");

        approval.setStatus(DENIED);

        eventPublisher.clearEvents();
        jdbcApprovalStore.addApproval(approval, defaultZoneId);

        assertThat(eventPublisher.getEventCount()).isOne();

        ApprovalModifiedEvent modifyEvent = eventPublisher.getLatestEvent();
        assertThat(modifyEvent.getSource()).isEqualTo(approval);
        assertThat(modifyEvent.getAuthentication()).isEqualTo(authentication);
        assertThat(addEvent.getAuditEvent().getData()).isEqualTo("{\"scope\":\"cloud_controller.read\",\"status\":\"DENIED\"}");
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
        return jdbcTemplate.queryForObject("select count(*) from authz_approvals where client_id=? and identity_zone_id = ?", Integer.class, new Object[]{clientId, zoneId});
    }

    private static int countUserApprovals(
            final JdbcTemplate jdbcTemplate,
            final String userId,
            final String zoneId) {
        return jdbcTemplate.queryForObject("select count(*) from authz_approvals where user_id=? and identity_zone_id = ?", Integer.class, new Object[]{userId, zoneId});
    }

    private static int countZoneApprovals(
            final JdbcTemplate jdbcTemplate,
            final String zoneId) {
        return jdbcTemplate.queryForObject("select count(*) from authz_approvals where identity_zone_id = ?", Integer.class, new Object[]{zoneId});
    }

}
