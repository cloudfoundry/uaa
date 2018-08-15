package org.cloudfoundry.identity.uaa.oauth.openid;

import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
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

    private HashSet<String> requestedResponseTypesWithIdToken;
    private HashSet<String> requestedResponseTypesWithoutIdToken;

    private BaseClientDetails clientWithoutOpenid;
    private BaseClientDetails clientWithOpenId;
    private IdTokenGranter idTokenGranter;
    private ApprovalService approvalService;
    private String userId;
    private BaseClientDetails clientDetails;

    @Before
    public void setup() {
        userId = "user";
        clientDetails = new BaseClientDetails();

        clientWithoutOpenid = new BaseClientDetails("clientId", null, "foo.read", null, null);
        clientWithOpenId = new BaseClientDetails("clientId", null, "foo.read,openid", null, null);

        requestedScopesWithoutOpenId = Sets.newHashSet("foo.read");
        requestedScopesWithOpenId = Sets.newHashSet("foo.read", "openid");

        validGrantTypeForIdToken = GRANT_TYPE_IMPLICIT;
        requestedResponseTypesWithIdToken = Sets.newHashSet("token", "id_token");
        requestedResponseTypesWithoutIdToken = Sets.newHashSet("token");
        approvalService = mock(ApprovalService.class);
        idTokenGranter = new IdTokenGranter(approvalService);
    }

    @Test
    public void shouldSend_isFalse_whenUserHasNotApprovedOpenidScope() {
        doThrow(InvalidTokenException.class).when(approvalService).ensureRequiredApprovals(any(), any(), any(), any());
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, validGrantTypeForIdToken, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenResponseTypeNotSpecified() {
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, validGrantTypeForIdToken, null));
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, validGrantTypeForIdToken, Sets.newHashSet()));
    }

    @Test
    public void shouldSend_isFalse_whenClientDoesNotHaveOpenIdScope() {
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithoutOpenid, requestedScopesWithOpenId, validGrantTypeForIdToken, requestedResponseTypesWithIdToken));
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientDetails, requestedScopesWithOpenId, validGrantTypeForIdToken, requestedResponseTypesWithIdToken));

        BaseClientDetails clientWithoutOpenidAndWithNullScope = new BaseClientDetails(clientWithoutOpenid);
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithoutOpenidAndWithNullScope, requestedScopesWithOpenId, validGrantTypeForIdToken, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenResponseTypeDoesNotHaveIdToken() {
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, validGrantTypeForIdToken, null));
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, validGrantTypeForIdToken, Sets.newHashSet()));
        HashSet<String> setWithNull = Sets.newHashSet();
        setWithNull.add(null);
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, validGrantTypeForIdToken, setWithNull));
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, validGrantTypeForIdToken, requestedResponseTypesWithoutIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenSAMLBearerGrantType() {
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_SAML2_BEARER, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenJwtBearerGrantType() {
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_USER_TOKEN, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenUserTokenGrantType() {
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_JWT_BEARER, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenClientCredentialsGrantType() {
        // Can't build an id_token without an associated user account which client_credentials does not have.
        assertFalse(idTokenGranter.shouldSendIdToken(null, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_CLIENT_CREDENTIALS, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenClientHasOpenIdScope_andNonOpenIdScopesAreRequested() {
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithoutOpenId, validGrantTypeForIdToken, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isTrue_whenClientHasOpenIdScope_andOpenIdScopeIsRequested_andIdTokenResponseType_GrantTypeIsImplicit() {
        assertTrue(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_IMPLICIT, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isTrue_whenClientHasOpenIdScope_andOpenIdScopeIsRequested_andIdTokenResponseType_GrantTypeIsRefresh() {
        assertTrue(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_REFRESH_TOKEN, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isTrue_whenAuthorizationCodeGrantIsUsed_withCodeResponseType() {
        // This is a special case for the authorization_code code flow. Per PM,
        // this is the only way that an id_token may be returned without the response
        // type of `id_token`. Check for user approvals and client scopes still applies.
        assertTrue(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE, Sets.newHashSet("code")));
    }

    @Test
    public void shouldSend_isFalse_whenAuthorizationCodeGrantIsUsed_withCodeResponseType_withInvalidClient() {
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithoutOpenid, requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE, Sets.newHashSet("code")));
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, null, GRANT_TYPE_AUTHORIZATION_CODE, Sets.newHashSet("code")));

        doThrow(InvalidTokenException.class).when(approvalService).ensureRequiredApprovals(any(), any(), any(), any());
        assertFalse(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE, Sets.newHashSet("code")));
    }

    @Test
    public void shouldSend_isTrue_whenClientHasOpenIdScope_andNoScopesRequested() {
        // When scopes are not explicitly requested, we default to the
        // full list of scopes configured on the client
        assertTrue(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, null, validGrantTypeForIdToken, requestedResponseTypesWithIdToken));
        assertTrue(idTokenGranter.shouldSendIdToken(userId, clientWithOpenId, Sets.newHashSet(), validGrantTypeForIdToken, requestedResponseTypesWithIdToken));
    }
}