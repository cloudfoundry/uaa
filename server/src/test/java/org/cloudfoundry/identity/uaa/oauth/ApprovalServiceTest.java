package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ApprovalServiceTest {
    private static final String CLIENT_ID = "cid";
    private static final String USER_ID = "user";

    private ApprovalService approvalService;
    private TimeService timeService;
    private ApprovalStore approvalStore;
    private UaaClientDetails clientDetails;

    @BeforeEach
    void setup() {
        timeService = mock(TimeService.class);
        approvalStore = mock(ApprovalStore.class);
        clientDetails = new UaaClientDetails(CLIENT_ID, null, "foo.read,bar.write", null, null);
        approvalService = new ApprovalService(timeService, approvalStore, new IdentityZoneManagerImpl());
    }

    @Test
    void ensureRequiredApprovals_happyCase() {
        long approvalExpiry = 10L;
        Approval approval = new Approval();
        approval.setScope("foo.read");
        approval.setStatus(Approval.ApprovalStatus.APPROVED);
        approval.setExpiresAt(new Date(approvalExpiry));
        when(timeService.getCurrentTimeMillis()).thenReturn(approvalExpiry - 1L);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        List<Approval> approvals = List.of(approval);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        List<String> requestedScopes = List.of("foo.read");
        approvalService.ensureRequiredApprovals(USER_ID, requestedScopes, GRANT_TYPE_AUTHORIZATION_CODE, clientDetails);
    }

    @Test
    void ensureRequiredApprovals_throwsWhenApprovalsExpired() {
        long approvalExpiry = 10L;
        Approval approval = new Approval();
        approval.setScope("foo.read");
        approval.setStatus(Approval.ApprovalStatus.APPROVED);
        approval.setExpiresAt(new Date(approvalExpiry));
        when(timeService.getCurrentTimeMillis()).thenReturn(approvalExpiry + 1L);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        List<Approval> approvals = List.of(approval);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);
        List<String> requestedScopes = List.of("foo.read");
        assertThatThrownBy(() -> approvalService.ensureRequiredApprovals(USER_ID, requestedScopes, GRANT_TYPE_AUTHORIZATION_CODE, clientDetails))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("approvals expired");
    }

    @Test
    void ensureRequiredApprovals_throwsWhenApprovalIsDenied() {
        long approvalExpiry = 10L;
        Approval approval = new Approval();
        approval.setScope("foo.read");
        approval.setStatus(Approval.ApprovalStatus.DENIED);
        approval.setExpiresAt(new Date(approvalExpiry));
        when(timeService.getCurrentTimeMillis()).thenReturn(approvalExpiry - 1L);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        List<Approval> approvals = List.of(approval);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);
        List<String> requestedScopes = List.of("foo.read");
        assertThatThrownBy(() ->
                approvalService.ensureRequiredApprovals(USER_ID, requestedScopes, GRANT_TYPE_AUTHORIZATION_CODE, clientDetails))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("requested scopes are not approved");
    }

    @Test
    void ensureRequiredApprovals_iteratesThroughAllApprovalsAndScopes() {
        long approvalExpiry = 10L;
        Approval approval1 = new Approval();
        approval1.setScope("foo.read");
        approval1.setStatus(Approval.ApprovalStatus.APPROVED);
        approval1.setExpiresAt(new Date(approvalExpiry));
        Approval approval2 = new Approval();
        approval2.setScope("bar.read");
        approval2.setStatus(Approval.ApprovalStatus.APPROVED);
        approval2.setExpiresAt(new Date(approvalExpiry));
        Approval approval3 = new Approval();
        approval3.setScope("baz.read");
        approval3.setStatus(Approval.ApprovalStatus.APPROVED);
        approval3.setExpiresAt(new Date(approvalExpiry));

        when(timeService.getCurrentTimeMillis()).thenReturn(approvalExpiry - 1L);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        List<Approval> approvals = List.of(approval1, approval2, approval3);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        assertThatNoException().isThrownBy(() ->
                approvalService.ensureRequiredApprovals(USER_ID, List.of("foo.read", "bar.read"), GRANT_TYPE_AUTHORIZATION_CODE, clientDetails));
    }

    @Test
    void ensureRequiredApprovals_throwsIfAnyRequestedScopesAreNotApproved() {
        long approvalExpiry = 10L;
        Approval approval1 = new Approval();
        approval1.setScope("foo.read");
        approval1.setStatus(Approval.ApprovalStatus.APPROVED);
        approval1.setExpiresAt(new Date(approvalExpiry));
        Approval approval2 = new Approval();
        approval2.setScope("bar.read");
        approval2.setStatus(Approval.ApprovalStatus.DENIED);
        approval2.setExpiresAt(new Date(approvalExpiry));
        Approval approval3 = new Approval();
        approval3.setScope("baz.read");
        approval3.setStatus(Approval.ApprovalStatus.APPROVED);
        approval3.setExpiresAt(new Date(approvalExpiry));

        when(timeService.getCurrentTimeMillis()).thenReturn(approvalExpiry - 1L);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        List<Approval> approvals = List.of(approval1, approval2, approval3);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);
        List<String> requestedScopes = List.of("foo.read", "bar.read");
        assertThatThrownBy(() -> approvalService.ensureRequiredApprovals(USER_ID, requestedScopes, GRANT_TYPE_AUTHORIZATION_CODE, clientDetails))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("requested scopes are not approved");
    }

    @Test
    void ensureRequiredApprovals_throwsWhenApprovalsMissing() {
        long approvalExpiry = 10L;
        Approval approval = new Approval();
        approval.setScope("bar.read");
        approval.setStatus(Approval.ApprovalStatus.APPROVED);
        approval.setExpiresAt(new Date(approvalExpiry));
        when(timeService.getCurrentTimeMillis()).thenReturn(approvalExpiry - 5L);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        List<Approval> approvals = List.of(approval);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        List<String> requestedScopes = List.of("foo.read");
        assertThatThrownBy(() ->
                approvalService.ensureRequiredApprovals(USER_ID, requestedScopes, GRANT_TYPE_AUTHORIZATION_CODE, clientDetails))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("requested scopes are not approved");
    }

    @Test
    void ensureRequiredApprovals_IfNoApprovalsNorScopes() {
        List<Approval> approvals = List.of();
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        assertThatNoException().isThrownBy(() ->
                approvalService.ensureRequiredApprovals(USER_ID, List.of(), GRANT_TYPE_AUTHORIZATION_CODE, clientDetails));
    }

    @Test
    void ensureRequiredApprovals_whenPasswordGrantType_autoApprovesAllScopes() {
        assertThatNoException().isThrownBy(() ->
                approvalService.ensureRequiredApprovals(USER_ID, List.of("hithere"), GRANT_TYPE_PASSWORD, clientDetails));
    }
}
