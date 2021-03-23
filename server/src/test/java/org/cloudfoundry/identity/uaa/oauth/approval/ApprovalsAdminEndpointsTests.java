package org.cloudfoundry.identity.uaa.oauth.approval;

import com.fasterxml.jackson.core.type.TypeReference;
import com.unboundid.scim.sdk.AttributePath;
import com.unboundid.scim.sdk.SCIMFilter;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.ApprovalsAdminEndpoints;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.*;

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class ApprovalsAdminEndpointsTests {
    private JdbcApprovalStore dao;

    private UaaUser marissa;

    private ApprovalsAdminEndpoints endpoints;

    private SecurityContextAccessor mockSecurityContextAccessor;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    PasswordEncoder passwordEncoder;

    @BeforeEach
    void initApprovalsAdminEndpointsTests() {
        UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);
        String id = UUID.randomUUID().toString();
        String userId = testAccounts.addUser(jdbcTemplate, id, IdentityZoneHolder.get().getId());

        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);
        when(mockIdentityZone.getConfig()).thenReturn(IdentityZone.getUaa().getConfig());

        UaaUserDatabase userDao = new JdbcUaaUserDatabase(jdbcTemplate, new TimeServiceImpl(), false, mockIdentityZoneManager);

        marissa = userDao.retrieveUserById(userId);
        assertNotNull(marissa);

        dao = new JdbcApprovalStore(jdbcTemplate);
        mockSecurityContextAccessor = mock(SecurityContextAccessor.class);
        when(mockSecurityContextAccessor.getUserName()).thenReturn(marissa.getUsername());
        when(mockSecurityContextAccessor.getUserId()).thenReturn(marissa.getId());
        when(mockSecurityContextAccessor.isUser()).thenReturn(true);

        MultitenantJdbcClientDetailsService clientDetailsService = new MultitenantJdbcClientDetailsService(jdbcTemplate, mockIdentityZoneManager, passwordEncoder);
        BaseClientDetails details = new BaseClientDetails("c1", "scim,clients", "read,write",
                "authorization_code, password, implicit, client_credentials", "update");
        details.setAutoApproveScopes(Collections.singletonList("true"));
        clientDetailsService.addClientDetails(details);

        endpoints = new ApprovalsAdminEndpoints(
                mockSecurityContextAccessor,
                dao,
                userDao,
                clientDetailsService);
    }

    private void addApproval(String userName, String scope, int expiresIn, ApprovalStatus status) {
        dao.addApproval(new Approval()
                .setUserId(userName)
                .setClientId("c1")
                .setScope(scope)
                .setExpiresAt(Approval.timeFromNow(expiresIn))
                .setStatus(status), IdentityZoneHolder.get().getId());
    }

    @AfterEach
    void cleanupDataSource() {
        jdbcTemplate.update("DELETE FROM authz_approvals");
        jdbcTemplate.update("DELETE FROM users");
        jdbcTemplate.update("DELETE FROM oauth_client_details");
    }

    @Test
    void validate_client_id_on_revoke() {
        assertThrowsWithMessageThat(NoSuchClientException.class,
                () -> endpoints.revokeApprovals("invalid_id"),
                is("No client with requested id: invalid_id"));
    }

    @Test
    void validate_client_id_on_update() {
        assertThrowsWithMessageThat(NoSuchClientException.class,
                () -> endpoints.updateClientApprovals("invalid_id", new Approval[0]),
                is("No client with requested id: invalid_id"));
    }

    @Test
    void canGetApprovals() {
        addApproval(marissa.getId(), "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "openid", 6000, APPROVED);

        assertEquals(3, endpoints.getApprovals("user_id pr", 1, 100).size());
        assertEquals(2, endpoints.getApprovals("user_id pr", 1, 2).size());
    }

    @Test
    void testApprovalsDeserializationIsCaseInsensitive() {
        Set<Approval> approvals = new HashSet<>();
        approvals.add(new Approval()
                .setUserId("test-user-id")
                .setClientId("testclientid")
                .setScope("scope")
                .setExpiresAt(new Date())
                .setStatus(ApprovalStatus.APPROVED));
        Set<Approval> deserializedApprovals = JsonUtils.readValue("[{\"userid\":\"test-user-id\",\"clientid\":\"testclientid\",\"scope\":\"scope\",\"status\":\"APPROVED\",\"expiresat\":\"2015-08-25T14:35:42.512Z\",\"lastupdatedat\":\"2015-08-25T14:35:42.512Z\"}]", new TypeReference<Set<Approval>>() {
        });
        assertEquals(approvals, deserializedApprovals);
    }

    @Test
    void canGetApprovalsWithAutoApproveTrue() {
        // Only get scopes that need approval
        addApproval(marissa.getId(), "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "openid", 6000, APPROVED);

        assertEquals(3, endpoints.getApprovals(userIdFilter(marissa.getId()), 1, 100).size());

        addApproval(marissa.getId(), "read", 12000, DENIED);
        addApproval(marissa.getId(), "write", 6000, APPROVED);

        assertEquals(3, endpoints.getApprovals(userIdFilter(marissa.getId()), 1, 100).size());
    }

    @Test
    void canUpdateApprovals() {
        addApproval(marissa.getId(), "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "openid", 6000, APPROVED);

        Approval[] app = new Approval[]{new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("uaa.user")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(APPROVED),
                new Approval()
                        .setUserId(marissa.getId())
                        .setClientId("c1")
                        .setScope("dash.user")
                        .setExpiresAt(Approval.timeFromNow(2000))
                        .setStatus(APPROVED),
                new Approval()
                        .setUserId(marissa.getId())
                        .setClientId("c1")
                        .setScope("openid")
                        .setExpiresAt(Approval.timeFromNow(2000))
                        .setStatus(DENIED),
                new Approval()
                        .setUserId(marissa.getId())
                        .setClientId("c1")
                        .setScope("cloud_controller.read")
                        .setExpiresAt(Approval.timeFromNow(2000))
                        .setStatus(APPROVED)};
        List<Approval> response = endpoints.updateApprovals(app);
        assertEquals(4, response.size());
        assertTrue(response.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("uaa.user")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(APPROVED)));
        assertTrue(response.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("dash.user")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(APPROVED)));
        assertTrue(response.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("openid")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(DENIED)));
        assertTrue(response.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("cloud_controller.read")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(APPROVED)));

        List<Approval> updatedApprovals = endpoints.getApprovals(userIdFilter(marissa.getId()), 1, 100);
        assertEquals(4, updatedApprovals.size());
        assertTrue(updatedApprovals.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("dash.user")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(APPROVED)));
        assertTrue(updatedApprovals.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("openid")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(DENIED)));
        assertTrue(updatedApprovals.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("cloud_controller.read")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(APPROVED)));
        assertTrue(updatedApprovals.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("uaa.user")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(APPROVED)));
    }

    @Test
    void attemptingToCreateDuplicateApprovalsExtendsValidity() {
        addApproval(marissa.getId(), "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "openid", 6000, APPROVED);

        addApproval(marissa.getId(), "openid", 10000, APPROVED);

        List<Approval> updatedApprovals = endpoints.getApprovals(userIdFilter(marissa.getId()), 1, 100);
        assertEquals(3, updatedApprovals.size());
        assertTrue(updatedApprovals.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("uaa.user")
                .setExpiresAt(Approval.timeFromNow(6000))
                .setStatus(APPROVED)));
        assertTrue(updatedApprovals.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("uaa.admin")
                .setExpiresAt(Approval.timeFromNow(12000))
                .setStatus(DENIED)));
        assertTrue(updatedApprovals.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("openid")
                .setExpiresAt(Approval.timeFromNow(10000))
                .setStatus(APPROVED)));
    }

    @Test
    void attemptingToCreateAnApprovalWithADifferentStatusUpdatesApproval() {
        addApproval(marissa.getId(), "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "openid", 6000, APPROVED);
        addApproval(marissa.getId(), "openid", 18000, DENIED);

        List<Approval> updatedApprovals = endpoints.getApprovals(userIdFilter(marissa.getId()), 1, 100);
        assertEquals(3, updatedApprovals.size());
        assertTrue(updatedApprovals.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("uaa.user")
                .setExpiresAt(Approval.timeFromNow(6000))
                .setStatus(APPROVED)));
        assertTrue(updatedApprovals.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("uaa.admin")
                .setExpiresAt(Approval.timeFromNow(12000))
                .setStatus(DENIED)));
        assertTrue(updatedApprovals.contains(new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("openid")
                .setExpiresAt(Approval.timeFromNow(18000))
                .setStatus(DENIED)));
    }

    @Test
    void userCannotUpdateApprovalsForAnotherUser() {
        addApproval(marissa.getId(), "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "openid", 6000, APPROVED);

        when(mockSecurityContextAccessor.getUserName()).thenReturn("vidya");
        when(mockSecurityContextAccessor.getUserId()).thenReturn("123456");

        Approval[] approvals = {new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("uaa.user")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(APPROVED)};

        assertThrows(UaaException.class, () -> endpoints.updateApprovals(approvals));
    }

    @Test
    void canRevokeApprovals() {
        addApproval(marissa.getId(), "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "openid", 6000, APPROVED);

        assertEquals(3, endpoints.getApprovals("user_id pr", 1, 100).size());
        assertEquals("ok", endpoints.revokeApprovals("c1").getStatus());
        assertEquals(0, endpoints.getApprovals("user_id pr", 1, 100).size());
    }

    private static String userIdFilter(String userId) {
        return SCIMFilter.createEqualityFilter(AttributePath.parse("user_id"), userId).getFilterValue();
    }

}
