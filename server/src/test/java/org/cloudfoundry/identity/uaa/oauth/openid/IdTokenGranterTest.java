package org.cloudfoundry.identity.uaa.oauth.openid;

import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.HashSet;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

public class IdTokenGranterTest {
    private HashSet<String> requestedScopesWithoutOpenId;
    private HashSet<String> requestedScopesWithOpenId;

    private String validGrantTypeForIdToken;

    private BaseClientDetails clientWithoutOpenid;
    private BaseClientDetails clientWithOpenId;
    private IdTokenGranter idTokenGranter;
    private ApprovalService approvalService;
    private UaaUser user;
    private BaseClientDetails clientDetails;

    @Before
    public void setup() {
        user = new UaaUser(new UaaUserPrototype().withId("user").withUsername("user").withEmail("user@example.com"));
        clientDetails = new BaseClientDetails();

        clientWithoutOpenid = new BaseClientDetails("clientId", null, "foo.read", null, null);
        clientWithOpenId = new BaseClientDetails("clientId", null, "foo.read,openid", null, null);

        requestedScopesWithoutOpenId = Sets.newHashSet("foo.read");
        requestedScopesWithOpenId = Sets.newHashSet("foo.read", "openid");

        validGrantTypeForIdToken = GRANT_TYPE_IMPLICIT;
        approvalService = mock(ApprovalService.class);
        idTokenGranter = new IdTokenGranter(approvalService);
    }

    @Test
    public void shouldSend_isFalse_whenUserHasNotApprovedOpenidScope() {
        doThrow(InvalidTokenException.class).when(approvalService).ensureRequiredApprovals(any(), any(), any(), any());
        assertFalse(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, validGrantTypeForIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenClientDoesNotHaveOpenIdScope() {
        assertFalse(idTokenGranter.shouldSendIdToken(user, clientWithoutOpenid, requestedScopesWithOpenId, validGrantTypeForIdToken));
        assertFalse(idTokenGranter.shouldSendIdToken(user, clientDetails, requestedScopesWithOpenId, validGrantTypeForIdToken));

        BaseClientDetails clientWithoutOpenidAndWithNullScope = new BaseClientDetails(clientWithoutOpenid);
        assertFalse(idTokenGranter.shouldSendIdToken(user, clientWithoutOpenidAndWithNullScope, requestedScopesWithOpenId, validGrantTypeForIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenSAMLBearerGrantType() {
        assertFalse(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_SAML2_BEARER));
    }

    @Test
    public void shouldSend_isFalse_whenJwtBearerGrantType() {
        assertFalse(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_USER_TOKEN));
    }

    @Test
    public void shouldSend_isFalse_whenUserTokenGrantType() {
        assertFalse(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_JWT_BEARER));
    }

    @Test
    public void shouldSend_isFalse_whenClientCredentialsGrantType() {
        // Can't build an id_token without an associated user account which client_credentials does not have.
        assertFalse(idTokenGranter.shouldSendIdToken(null, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_CLIENT_CREDENTIALS));
    }

    @Test
    public void shouldSend_isFalse_whenClientHasOpenIdScope_andNonOpenIdScopesAreRequested() {
        assertFalse(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithoutOpenId, validGrantTypeForIdToken));
    }

    @Test
    public void shouldSend_isTrue_whenClientHasOpenIdScope_andOpenIdScopeIsRequested_andIdTokenResponseType_GrantTypeIsImplicit() {
        assertTrue(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_IMPLICIT));
    }

    @Test
    public void shouldSend_isTrue_whenClientHasOpenIdScope_andOpenIdScopeIsRequested_andIdTokenResponseType_GrantTypeIsRefresh() {
        assertTrue(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_REFRESH_TOKEN));
    }

    @Test
    public void shouldSend_isTrue_whenAuthorizationCodeGrantIsUsed_withCodeResponseType() {
        assertTrue(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE));
    }

    @Test
    public void shouldSend_isFalse_whenAuthorizationCodeGrantIsUsed_withCodeResponseType_withClientWithoutOpenId() {
        assertFalse(idTokenGranter.shouldSendIdToken(user, clientWithoutOpenid, requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE));
    }

    @Test
    public void shouldSend_isFalse_whenAuthorizationCodeGrantIsUsed_withCodeResponseType_withUnapprovedOpenId() {
        doThrow(InvalidTokenException.class).when(approvalService).ensureRequiredApprovals(any(), any(), any(), any());
        assertFalse(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE));
    }

    @Test
    public void shouldSend_isTrue_whenClientHasOpenIdScope_andNoScopesRequested() {
        // When scopes are not explicitly requested, we default to the
        // full list of scopes configured on the client
        assertTrue(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, null, validGrantTypeForIdToken));
        assertTrue(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, Sets.newHashSet(), validGrantTypeForIdToken));
    }
}