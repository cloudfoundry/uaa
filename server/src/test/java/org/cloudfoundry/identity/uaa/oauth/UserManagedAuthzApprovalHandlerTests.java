package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.*;

import static java.util.Collections.singleton;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

public class UserManagedAuthzApprovalHandlerTests extends JdbcTestBase {

    private final UserManagedAuthzApprovalHandler handler = new UserManagedAuthzApprovalHandler();
    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

    private ApprovalStore approvalStore = null;

    private String userId = null;
    private TestAuthentication userAuthentication;

    @Before
    public void initUserManagedAuthzApprovalHandlerTests() {
        approvalStore = new JdbcApprovalStore(jdbcTemplate);
        handler.setApprovalStore(approvalStore);
        handler.setClientDetailsService(
                mockClientDetailsService(
                        "foo",
                        new String[]{
                                "cloud_controller.read",
                                "cloud_controller.write",
                                "openid",
                                "space.*.developer"
                        },
                        Collections.emptySet()
                )
        );
        userId = new RandomValueStringGenerator().generate();
        testAccounts.addUser(jdbcTemplate, userId, IdentityZoneHolder.get().getId());
        userAuthentication = new TestAuthentication(userId, testAccounts.getUserName(), true);
    }

    @After
    public void cleanupDataSource() {
        TestUtils.deleteFrom(jdbcTemplate, "authz_approvals");
        assertThat(jdbcTemplate.queryForObject("select count(*) from authz_approvals", Integer.class), is(0));
    }

    @Test
    public void noScopeApproval() {
        AuthorizationRequest request = new AuthorizationRequest("testclient", Collections.emptySet());
        request.setApproved(true);
        // The request is approved but does not request any scopes. The user has
        // also not approved any scopes. Approved.
        assertTrue(handler.isApproved(request, userAuthentication));
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
        assertFalse(handler.isApproved(request, userAuthentication));
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
        assertFalse(handler.isApproved(request, userAuthentication));
    }

    @Test
    public void noRequestedScopesButSomeApprovedScopes() {
        AuthorizationRequest request = new AuthorizationRequest("foo", new HashSet<>());
        request.setApproved(false);

        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);

        approvalStore.addApproval(new Approval()
                .setUserId(userAuthentication.getId())
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userAuthentication.getId())
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is approved because the user has not requested any scopes
        assertTrue(handler.isApproved(request, userAuthentication));
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

        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);

        approvalStore.addApproval(new Approval()
                .setUserId(userAuthentication.getId())
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userAuthentication.getId())
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is not approved because the user has not yet approved the
        // scopes requested
        assertFalse(handler.isApproved(request, userAuthentication));
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

        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);

        approvalStore.addApproval(new Approval()
                .setUserId(userAuthentication.getId())
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userAuthentication.getId())
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is not approved because the user has not yet approved all
        // the scopes requested
        assertFalse(handler.isApproved(request, userAuthentication));
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

        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);

        handler.setClientDetailsService(
                mockClientDetailsService(
                        "foo",
                        new String[]{
                                "cloud_controller.read",
                                "cloud_controller.write",
                                "openid"
                        },
                        singleton("true")
                )
        );

        approvalStore.addApproval(new Approval()
                .setUserId(userAuthentication.getId())
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userAuthentication.getId())
                .setClientId("foo")
                .setScope("openid")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        assertTrue(handler.isApproved(request, userAuthentication));
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

        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);

        approvalStore.addApproval(new Approval()
                .setUserId(userAuthentication.getId())
                .setClientId("foo")
                .setScope("cloud_controller.read")
                .setExpiresAt(nextWeek)
                .setStatus(APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userAuthentication.getId())
                .setClientId("foo")
                .setScope("cloud_controller.write")
                .setExpiresAt(nextWeek)
                .setStatus(DENIED), IdentityZoneHolder.get().getId());

        // The request is not approved because the user has not yet approved all
        // the scopes requested
        assertFalse(handler.isApproved(request, userAuthentication));
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
        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);

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
        assertTrue(handler.isApproved(request, userAuthentication));
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
        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);

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
        assertTrue(handler.isApproved(request, userAuthentication));
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
        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);

        handler.setClientDetailsService(mockClientDetailsService(
                "foo",
                new String[]{
                        "cloud_controller.read",
                        "cloud_controller.write",
                        "openid"
                },
                singleton("cloud_controller.write")));

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
        assertTrue(handler.isApproved(request, userAuthentication));
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
        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);
        Set<String> autoApprovedScopes = new HashSet<>();
        autoApprovedScopes.add("space.*.developer");
        autoApprovedScopes.add("cloud_controller.write");

        handler.setClientDetailsService(mockClientDetailsService(
                "foo",
                new String[]{
                        "cloud_controller.read",
                        "cloud_controller.write",
                        "openid",
                        "space.*.developer"
                }, autoApprovedScopes));

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
        assertTrue(handler.isApproved(request, userAuthentication));
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
        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);

        handler.setClientDetailsService(mockClientDetailsService(
                "foo",
                new String[]{
                        "cloud_controller.read",
                        "cloud_controller.write",
                        "openid",
                        "space.*.developer"
                },
                singleton("true")));

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
        assertTrue(handler.isApproved(request, userAuthentication));
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
        long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
        Date nextWeek = new Date(theFuture);

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
        assertTrue(handler.isApproved(request, userAuthentication));
        assertEquals(new HashSet<>(Collections.singletonList("openid")), request.getScope());
    }

    private static QueryableResourceManager<ClientDetails> mockClientDetailsService(String id, String[] scope, Set<String> autoApprovedScopes) {
        @SuppressWarnings("unchecked")
        QueryableResourceManager<ClientDetails> service = mock(QueryableResourceManager.class);
        BaseClientDetails details = mock(BaseClientDetails.class);
        Mockito.when(service.retrieve(id, IdentityZoneHolder.get().getId())).thenReturn(details);
        Mockito.when(details.getScope()).thenReturn(new HashSet<>(Arrays.asList(scope)));
        Mockito.when(details.getAutoApproveScopes()).thenReturn(autoApprovedScopes);
        return service;
    }

    @SuppressWarnings("serial")
    protected static class TestAuthentication extends AbstractAuthenticationToken {
        private final String principal;

        private String name;
        private String id;

        TestAuthentication(String id, String name, boolean authenticated) {
            super(null);
            setAuthenticated(authenticated);
            this.principal = name;
            this.name = name;
            this.id = id;
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public String getPrincipal() {
            return this.principal;
        }

        @Override
        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getId() {
            return id;
        }

    }

}
