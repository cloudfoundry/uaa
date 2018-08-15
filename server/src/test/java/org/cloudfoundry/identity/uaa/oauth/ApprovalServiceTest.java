package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Date;
import java.util.List;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ApprovalServiceTest {
    private static final String CLIENT_ID = "cid";
    private static final String USER_ID = "user";

    private ApprovalService approvalService;
    private TimeService timeService;
    private ApprovalStore approvalStore;
    private BaseClientDetails clientDetails;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setup() {
        timeService = mock(TimeService.class);
        approvalStore = mock(ApprovalStore.class);
        clientDetails = new BaseClientDetails(CLIENT_ID, null, "foo.read,bar.write", null, null);
        approvalService = new ApprovalService(timeService, approvalStore);
    }

    @Test
    public void ensureRequiredApprovals_happyCase() {
        long approvalExpiry = 10L;
        Approval approval = new Approval();
        approval.setScope("foo.read");
        approval.setStatus(Approval.ApprovalStatus.APPROVED);
        approval.setExpiresAt(new Date(approvalExpiry));
        when(timeService.getCurrentTimeMillis()).thenReturn(approvalExpiry - 1L);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        List<Approval> approvals = Lists.newArrayList(approval);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        approvalService.ensureRequiredApprovals(USER_ID, Lists.newArrayList("foo.read"), GRANT_TYPE_AUTHORIZATION_CODE, clientDetails);
    }

    @Test
    public void ensureRequiredApprovals_throwsWhenApprovalsExpired() {
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("approvals expired");

        long approvalExpiry = 10L;
        Approval approval = new Approval();
        approval.setScope("foo.read");
        approval.setStatus(Approval.ApprovalStatus.APPROVED);
        approval.setExpiresAt(new Date(approvalExpiry));
        when(timeService.getCurrentTimeMillis()).thenReturn(approvalExpiry + 1L);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        List<Approval> approvals = Lists.newArrayList(approval);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        approvalService.ensureRequiredApprovals(USER_ID, Lists.newArrayList("foo.read"), GRANT_TYPE_AUTHORIZATION_CODE, clientDetails);
    }

    @Test
    public void ensureRequiredApprovals_throwsWhenApprovalIsDenied() {
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("requested scopes are not approved");

        long approvalExpiry = 10L;
        Approval approval = new Approval();
        approval.setScope("foo.read");
        approval.setStatus(Approval.ApprovalStatus.DENIED);
        approval.setExpiresAt(new Date(approvalExpiry));
        when(timeService.getCurrentTimeMillis()).thenReturn(approvalExpiry - 1L);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        List<Approval> approvals = Lists.newArrayList(approval);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        approvalService.ensureRequiredApprovals(USER_ID, Lists.newArrayList("foo.read"), GRANT_TYPE_AUTHORIZATION_CODE, clientDetails);
    }

    @Test
    public void ensureRequiredApprovals_iteratesThroughAllApprovalsAndScopes() {
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

        List<Approval> approvals = Lists.newArrayList(approval1, approval2, approval3);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        approvalService.ensureRequiredApprovals(USER_ID, Lists.newArrayList("foo.read", "bar.read"), GRANT_TYPE_AUTHORIZATION_CODE, clientDetails);
    }

    @Test
    public void ensureRequiredApprovals_throwsIfAnyRequestedScopesAreNotApproved() {
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("requested scopes are not approved");

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

        List<Approval> approvals = Lists.newArrayList(approval1, approval2, approval3);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        approvalService.ensureRequiredApprovals(USER_ID, Lists.newArrayList("foo.read", "bar.read"), GRANT_TYPE_AUTHORIZATION_CODE, clientDetails);
    }

    @Test
    public void ensureRequiredApprovals_throwsWhenApprovalsMissing() {
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("requested scopes are not approved");

        long approvalExpiry = 10L;
        Approval approval = new Approval();
        approval.setScope("bar.read");
        approval.setStatus(Approval.ApprovalStatus.APPROVED);
        approval.setExpiresAt(new Date(approvalExpiry));
        when(timeService.getCurrentTimeMillis()).thenReturn(approvalExpiry - 5L);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        List<Approval> approvals = Lists.newArrayList(approval);
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        approvalService.ensureRequiredApprovals(USER_ID, Lists.newArrayList("foo.read"), GRANT_TYPE_AUTHORIZATION_CODE, clientDetails);
    }

    @Test
    public void ensureRequiredApprovals_IfNoApprovalsNorScopes() {
        List<Approval> approvals = Lists.newArrayList();
        when(approvalStore.getApprovals(eq(USER_ID), eq(CLIENT_ID), anyString())).thenReturn(approvals);

        approvalService.ensureRequiredApprovals(USER_ID, Lists.newArrayList(), GRANT_TYPE_AUTHORIZATION_CODE, clientDetails);
    }

    @Test
    public void ensureRequiredApprovals_whenPasswordGrantType_autoapprovesAllScopes() {
        approvalService.ensureRequiredApprovals(USER_ID, Lists.newArrayList("hithere"), GRANT_TYPE_PASSWORD, clientDetails);
        // no exception expected
    }
}
