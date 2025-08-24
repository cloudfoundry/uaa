package org.cloudfoundry.identity.uaa.oauth.openid;

import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

class IdTokenGranterTest {
    private HashSet<String> requestedScopesWithoutOpenId;
    private HashSet<String> requestedScopesWithOpenId;

    private String validGrantTypeForIdToken;

    private UaaClientDetails clientWithoutOpenid;
    private UaaClientDetails clientWithOpenId;
    private IdTokenGranter idTokenGranter;
    private ApprovalService approvalService;
    private UaaUser user;
    private UaaClientDetails clientDetails;

    @BeforeEach
    void setup() {
        user = new UaaUser(new UaaUserPrototype().withId("user").withUsername("user").withEmail("user@example.com"));
        clientDetails = new UaaClientDetails();

        clientWithoutOpenid = new UaaClientDetails("clientId", null, "foo.read", null, null);
        clientWithOpenId = new UaaClientDetails("clientId", null, "foo.read,openid", null, null);

        requestedScopesWithoutOpenId = Sets.newHashSet("foo.read");
        requestedScopesWithOpenId = Sets.newHashSet("foo.read", "openid");

        validGrantTypeForIdToken = GRANT_TYPE_IMPLICIT;
        approvalService = mock(ApprovalService.class);
        idTokenGranter = new IdTokenGranter(approvalService);
    }

    @Test
    void shouldSend_isFalse_whenUserHasNotApprovedOpenidScope() {
        doThrow(InvalidTokenException.class).when(approvalService).ensureRequiredApprovals(any(), any(), any(), any());
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, validGrantTypeForIdToken)).isFalse();
    }

    @Test
    void shouldSend_isFalse_whenClientDoesNotHaveOpenIdScope() {
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithoutOpenid, requestedScopesWithOpenId, validGrantTypeForIdToken)).isFalse();
        assertThat(idTokenGranter.shouldSendIdToken(user, clientDetails, requestedScopesWithOpenId, validGrantTypeForIdToken)).isFalse();

        UaaClientDetails clientWithoutOpenidAndWithNullScope = new UaaClientDetails(clientWithoutOpenid);
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithoutOpenidAndWithNullScope, requestedScopesWithOpenId, validGrantTypeForIdToken)).isFalse();
    }

    @Test
    void shouldSend_isFalse_whenSAMLBearerGrantType() {
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_SAML2_BEARER)).isFalse();
    }

    @Test
    void shouldSend_isTrue_whenJwtBearerGrantType() {
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_JWT_BEARER)).isTrue();
    }

    @Test
    void shouldSend_isTrue_whenJTokenExchangeGrantType() {
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_TOKEN_EXCHANGE)).isTrue();
    }

    @Test
    void shouldSend_isFalse_whenUserTokenGrantType() {
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_USER_TOKEN)).isFalse();
    }

    @Test
    void shouldSend_isFalse_whenClientCredentialsGrantType() {
        // Can't build an id_token without an associated user account which client_credentials does not have.
        assertThat(idTokenGranter.shouldSendIdToken(null, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_CLIENT_CREDENTIALS)).isFalse();
    }

    @Test
    void shouldSend_isFalse_whenClientHasOpenIdScope_andNonOpenIdScopesAreRequested() {
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithoutOpenId, validGrantTypeForIdToken)).isFalse();
    }

    @Test
    void shouldSend_isTrue_whenClientHasOpenIdScope_andOpenIdScopeIsRequested_andIdTokenResponseType_GrantTypeIsImplicit() {
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_IMPLICIT)).isTrue();
    }

    @Test
    void shouldSend_isTrue_whenClientHasOpenIdScope_andOpenIdScopeIsRequested_andIdTokenResponseType_GrantTypeIsRefresh() {
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_REFRESH_TOKEN)).isTrue();
    }

    @Test
    void shouldSend_isTrue_whenAuthorizationCodeGrantIsUsed_withCodeResponseType() {
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE)).isTrue();
    }

    @Test
    void shouldSend_isFalse_whenAuthorizationCodeGrantIsUsed_withCodeResponseType_withClientWithoutOpenId() {
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithoutOpenid, requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE)).isFalse();
    }

    @Test
    void shouldSend_isFalse_whenAuthorizationCodeGrantIsUsed_withCodeResponseType_withUnapprovedOpenId() {
        doThrow(InvalidTokenException.class).when(approvalService).ensureRequiredApprovals(any(), any(), any(), any());
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE)).isFalse();
    }

    @Test
    void shouldSend_isTrue_whenClientHasOpenIdScope_andNoScopesRequested() {
        // When scopes are not explicitly requested, we default to the
        // full list of scopes configured on the client
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, null, validGrantTypeForIdToken)).isTrue();
        assertThat(idTokenGranter.shouldSendIdToken(user, clientWithOpenId, Sets.newHashSet(), validGrantTypeForIdToken)).isTrue();
    }
}