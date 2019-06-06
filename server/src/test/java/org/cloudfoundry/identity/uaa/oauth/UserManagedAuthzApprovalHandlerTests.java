package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
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
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserManagedAuthzApprovalHandlerTests extends JdbcTestBase {

    private UserManagedAuthzApprovalHandler handler;

    private ApprovalStore approvalStore;
    private BaseClientDetails mockBaseClientDetails;

    private String userId;

    private interface AuthenticationWithGetId extends Authentication {
        String getId();
    }

    private AuthenticationWithGetId mockAuthentication;

    private Date nextWeek;

    @Before
    public void initUserManagedAuthzApprovalHandlerTests() {
        approvalStore = new JdbcApprovalStore(jdbcTemplate);
        QueryableResourceManager<ClientDetails> mockClientDetailsService = mock(QueryableResourceManager.class);
        mockBaseClientDetails = mock(BaseClientDetails.class);
        when(mockClientDetailsService.retrieve("foo", IdentityZoneHolder.get().getId())).thenReturn(mockBaseClientDetails);
        when(mockBaseClientDetails.getScope()).thenReturn(new HashSet<>(Arrays.asList(
                "cloud_controller.read",
                "cloud_controller.write",
                "openid",
                "space.*.developer")));
        when(mockBaseClientDetails.getAutoApproveScopes()).thenReturn(Collections.emptySet());
        handler = new UserManagedAuthzApprovalHandler(approvalStore, mockClientDetailsService);

        userId = "userId-" + new RandomValueStringGenerator().generate();
        mockAuthentication = mock(AuthenticationWithGetId.class);
        when(mockAuthentication.isAuthenticated()).thenReturn(true);
        when(mockAuthentication.getId()).thenReturn(userId);

        nextWeek = new Date(LocalDateTime
                .now()
                .plus(Duration.ofDays(7))
                .atZone(ZoneId.systemDefault()).toEpochSecond() * 1000);
    }

    @After
    public void cleanupDataSource() {
        jdbcTemplate.update("delete from authz_approvals");
    }

    @Test
    public void noScopeApproval() {
        AuthorizationRequest request = new AuthorizationRequest("testclient", Collections.emptySet());
        request.setApproved(true);
        // The request is approved but does not request any scopes. The user has
        // also not approved any scopes. Approved.
        assertTrue(handler.isApproved(request, mockAuthentication));
    }

    @Test
    public void noPreviouslyApprovedScopes() {
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
    public void authzApprovedButNoPreviouslyApprovedScopes() {
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
    public void noRequestedScopesButSomeApprovedScopes() {
        AuthorizationRequest request = new AuthorizationRequest("foo", new HashSet<>());
        request.setApproved(false);

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is approved because the user has not requested any scopes
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertEquals(0, request.getScope().size());
    }

    @Test
    public void requestedScopesDontMatchApprovalsAtAll() {
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
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is not approved because the user has not yet approved the
        // scopes requested
        assertFalse(handler.isApproved(request, mockAuthentication));
    }

    @Test
    public void onlySomeRequestedScopeMatchesApproval() {
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
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is not approved because the user has not yet approved all
        // the scopes requested
        assertFalse(handler.isApproved(request, mockAuthentication));
    }

    @Test
    public void onlySomeRequestedScopeMatchesDeniedApprovalButScopeAutoApproved() {
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
                .setStatus(DENIED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("openid")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        assertTrue(handler.isApproved(request, mockAuthentication));
        assertEquals(new HashSet<>(Arrays.asList("cloud_controller.read", "openid")), request.getScope());
    }

    @Test
    public void requestedScopesMatchApprovalButAdditionalScopesRequested() {
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
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is not approved because the user has not yet approved all
        // the scopes requested
        assertFalse(handler.isApproved(request, mockAuthentication));
    }

    @Test
    public void allRequestedScopesMatchApproval() {
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
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());

        // The request is approved because the user has approved all the scopes
        // requested
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertEquals(new HashSet<>(Arrays.asList("openid", "cloud_controller.read", "cloud_controller.write")), request.getScope());
    }

    @Test
    public void requestedScopesMatchApprovalButSomeDenied() {
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
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is approved because the user has acted on all requested
        // scopes
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertEquals(new HashSet<>(Arrays.asList("openid", "cloud_controller.read")), request.getScope());
    }

    @Test
    public void requestedScopesMatchApprovalSomeDeniedButDeniedScopesAutoApproved() {
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
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is not approved because the user has denied some of the
        // scopes requested
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertThat(
                request.getScope(),
                Matchers.containsInAnyOrder("openid", "cloud_controller.read", "cloud_controller.write")
        );
    }

    @Test
    public void requestedScopesMatchApprovalSomeDeniedButDeniedScopesAutoApprovedByWildcard() {
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
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("space.1.developer")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is not approved because the user has denied some of the
        // scopes requested
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertThat(
                request.getScope(),
                Matchers.containsInAnyOrder("openid", "cloud_controller.read", "cloud_controller.write", "space.1.developer", "space.2.developer")
        );
    }

    @Test
    public void requestedScopesMatchByWildcard() {
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
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("space.1.developer")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is not approved because the user has denied some of the
        // scopes requested
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertThat(
                request.getScope(),
                Matchers.containsInAnyOrder("openid", "cloud_controller.read", "cloud_controller.write", "space.1.developer")
        );
    }

    @Test
    public void someRequestedScopesMatchApproval() {
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
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());

        // The request is approved because the user has approved all the scopes
        // requested
        assertTrue(handler.isApproved(request, mockAuthentication));
        assertEquals(new HashSet<>(Collections.singletonList("openid")), request.getScope());
    }

}
