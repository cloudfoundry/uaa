package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static java.util.Collections.singleton;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class UserManagedAuthzApprovalHandlerTests {

    private UserManagedAuthzApprovalHandler handler;

    private ApprovalStore approvalStore;
    private BaseClientDetails mockBaseClientDetails;

    private String userId;

    private interface AuthenticationWithGetId extends Authentication {
        String getId();
    }

    private AuthenticationWithGetId mockAuthentication;
    private Date nextWeek;
    private String currentIdentityZoneId;

    @BeforeEach
    void setUp(@Autowired JdbcTemplate jdbcTemplate) {
        RandomValueStringGenerator generator = new RandomValueStringGenerator();
        currentIdentityZoneId = "currentIdentityZoneId-" + generator.generate();
        approvalStore = new JdbcApprovalStore(jdbcTemplate);

        QueryableResourceManager<ClientDetails> mockClientDetailsService = mock(QueryableResourceManager.class);
        mockBaseClientDetails = mock(BaseClientDetails.class);
        when(mockClientDetailsService.retrieve("foo",
                currentIdentityZoneId)).thenReturn(mockBaseClientDetails);
        when(mockBaseClientDetails.getScope()).thenReturn(new HashSet<>(Arrays.asList(
                "cloud_controller.read",
                "cloud_controller.write",
                "openid",
                "space.*.developer")));
        when(mockBaseClientDetails.getAutoApproveScopes()).thenReturn(Collections.emptySet());

        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);

        handler = new UserManagedAuthzApprovalHandler(approvalStore, mockClientDetailsService, mockIdentityZoneManager);

        userId = "userId-" + generator.generate();
        mockAuthentication = mock(AuthenticationWithGetId.class);
        when(mockAuthentication.isAuthenticated()).thenReturn(true);
        when(mockAuthentication.getId()).thenReturn(userId);

        nextWeek = new Date(LocalDateTime
                .now()
                .plus(Duration.ofDays(7))
                .atZone(ZoneId.systemDefault()).toEpochSecond() * 1000);
    }

    @AfterEach
    void tearDown(@Autowired JdbcTemplate jdbcTemplate) {
        jdbcTemplate.update("delete from authz_approvals");
    }

    @Test
    void noScopeApproval() {
        AuthorizationRequest request = new AuthorizationRequest("testclient", Collections.emptySet());
        request.setApproved(true);
        // The request is approved but does not request any scopes. The user has
        // also not approved any scopes. Approved.
        assertTrue(handler.isApproved(request, mockAuthentication));
    }

    @Test
    void noPreviouslyApprovedScopes() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Arrays.asList("cloud_controller.read", "cloud_controller.write")
                )
        );
        request.setApproved(false);
        // The request needs user approval for scopes. The user has also not
        // approved any scopes prior to this request.
        // Not approved.
        assertFalse(handler.isApproved(request, mockAuthentication));
    }

    @Test
    void authzApprovedButNoPreviouslyApprovedScopes() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Arrays.asList("cloud_controller.read", "cloud_controller.write")
                )
        );
        request.setApproved(true);
        // The request needs user approval for scopes. The user has also not
        // approved any scopes prior to this request.
        // Not approved.
        assertFalse(handler.isApproved(request, mockAuthentication));
    }

    @Test
    void noRequestedScopesButSomeApprovedScopes() {
        AuthorizationRequest request = new AuthorizationRequest("foo", new HashSet<>());
        request.setApproved(false);

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);

        // The request is approved because the user has not requested any scopes
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertEquals(0, request.getScope().size());
    }

    @Test
    void requestedScopesDontMatchApprovalsAtAll() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Collections.singletonList("openid")
                )
        );
        request.setApproved(false);

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);

        // The request is not approved because the user has not yet approved the
        // scopes requested
        assertFalse(handler.isApproved(request, mockAuthentication));
    }

    @Test
    void onlySomeRequestedScopeMatchesApproval() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Arrays.asList("openid", "cloud_controller.read")
                )
        );
        request.setApproved(false);

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);

        // The request is not approved because the user has not yet approved all
        // the scopes requested
        assertFalse(handler.isApproved(request, mockAuthentication));
    }

    @Test
    void onlySomeRequestedScopeMatchesDeniedApprovalButScopeAutoApproved() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Arrays.asList("openid", "cloud_controller.read")
                )
        );
        request.setApproved(false);

        when(mockBaseClientDetails.getScope()).thenReturn(new HashSet<>(Arrays.asList(
                "cloud_controller.read",
                "cloud_controller.write",
                "openid")));
        when(mockBaseClientDetails.getAutoApproveScopes()).thenReturn(singleton("true"));

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("openid")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);

        assertTrue(handler.isApproved(request, mockAuthentication));
        assertEquals(new HashSet<>(Arrays.asList("cloud_controller.read", "openid")), request.getScope());
    }

    @Test
    void requestedScopesMatchApprovalButAdditionalScopesRequested() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Arrays.asList(
                                "openid",
                                "cloud_controller.read",
                                "cloud_controller.write"
                        )
                )
        );
        request.setApproved(false);

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);

        // The request is not approved because the user has not yet approved all
        // the scopes requested
        assertFalse(handler.isApproved(request, mockAuthentication));
    }

    @Test
    void allRequestedScopesMatchApproval() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Arrays.asList(
                                "openid",
                                "cloud_controller.read",
                                "cloud_controller.write"
                        )
                )
        );
        request.setApproved(false);

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("openid")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);

        // The request is approved because the user has approved all the scopes
        // requested
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertEquals(new HashSet<>(Arrays.asList("openid", "cloud_controller.read", "cloud_controller.write")), request.getScope());
    }

    @Test
    void requestedScopesMatchApprovalButSomeDenied() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Arrays.asList(
                                "openid",
                                "cloud_controller.read",
                                "cloud_controller.write"
                        )
                )
        );
        request.setApproved(false);

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("openid")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);

        // The request is approved because the user has acted on all requested
        // scopes
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertEquals(new HashSet<>(Arrays.asList("openid", "cloud_controller.read")), request.getScope());
    }

    @Test
    void requestedScopesMatchApprovalSomeDeniedButDeniedScopesAutoApproved() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Arrays.asList(
                                "openid",
                                "cloud_controller.read",
                                "cloud_controller.write"
                        )
                )
        );
        request.setApproved(false);

        when(mockBaseClientDetails.getScope()).thenReturn(new HashSet<>(Arrays.asList(
                "cloud_controller.read",
                "cloud_controller.write",
                "openid")));
        when(mockBaseClientDetails.getAutoApproveScopes()).thenReturn(singleton("cloud_controller.write"));

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("openid")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);

        // The request is not approved because the user has denied some of the
        // scopes requested
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertThat(
                request.getScope(),
                Matchers.containsInAnyOrder("openid", "cloud_controller.read", "cloud_controller.write")
        );
    }

    @Test
    void requestedScopesMatchApprovalSomeDeniedButDeniedScopesAutoApprovedByWildcard() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Arrays.asList(
                                "openid",
                                "cloud_controller.read",
                                "cloud_controller.write",
                                "space.1.developer",
                                "space.2.developer"
                        )
                )
        );
        request.setApproved(false);
        Set<String> autoApprovedScopes = new HashSet<>();
        autoApprovedScopes.add("space.*.developer");
        autoApprovedScopes.add("cloud_controller.write");

        when(mockBaseClientDetails.getAutoApproveScopes()).thenReturn(autoApprovedScopes);

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("openid")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("space.1.developer")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);

        // The request is not approved because the user has denied some of the
        // scopes requested
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertThat(
                request.getScope(),
                Matchers.containsInAnyOrder("openid", "cloud_controller.read", "cloud_controller.write", "space.1.developer", "space.2.developer")
        );
    }

    @Test
    void requestedScopesMatchByWildcard() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(
                        Arrays.asList(
                                "openid",
                                "cloud_controller.read",
                                "cloud_controller.write",
                                "space.1.developer"
                        )
                )
        );
        request.setApproved(false);

        when(mockBaseClientDetails.getAutoApproveScopes()).thenReturn(singleton("true"));

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("openid")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("space.1.developer")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED),
                currentIdentityZoneId);

        // The request is not approved because the user has denied some of the
        // scopes requested
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertThat(
                request.getScope(),
                Matchers.containsInAnyOrder("openid", "cloud_controller.read", "cloud_controller.write", "space.1.developer")
        );
    }

    @Test
    void someRequestedScopesMatchApproval() {
        AuthorizationRequest request = new AuthorizationRequest(
                "foo",
                new HashSet<>(Collections.singletonList("openid"))
        );
        request.setApproved(false);

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("openid")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED),
                currentIdentityZoneId);

        // The request is approved because the user has approved all the scopes
        // requested
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertEquals(new HashSet<>(Collections.singletonList("openid")), request.getScope());
    }

}
