package org.cloudfoundry.identity.uaa.oauth.openid;

import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthUserAuthority;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.*;
import static org.junit.Assert.*;

public class IdTokenGranterTest {
    private HashSet<String> requestedScopesWithoutOpenId;
    private HashSet<String> requestedScopesWithOpenId;

    private String nonClientCredentialsGrantType;

    private HashSet<String> requestedResponseTypesWithIdToken;
    private HashSet<String> requestedResponseTypesWithoutIdToken;

    private BaseClientDetails clientWithoutOpenid;
    private BaseClientDetails clientWithOpenId;
    private IdTokenGranter idTokenGranter;

    @Before
    public void setup() {
        clientWithoutOpenid = new BaseClientDetails("clientId", null, "foo.read", "authorization_code", null);
        clientWithOpenId = new BaseClientDetails("clientId", null, "foo.read,openid", "authorization_code", null);

        requestedScopesWithoutOpenId = Sets.newHashSet("foo.read");
        requestedScopesWithOpenId = Sets.newHashSet("foo.read", "openid");

        nonClientCredentialsGrantType = GRANT_TYPE_PASSWORD;
        requestedResponseTypesWithIdToken = Sets.newHashSet("token", "id_token");
        requestedResponseTypesWithoutIdToken = Sets.newHashSet("token");
        idTokenGranter = new IdTokenGranter();
    }

    @Test
    public void shouldSend_isFalse_whenResponseTypeNotSpecified() {
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, nonClientCredentialsGrantType, null));
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, nonClientCredentialsGrantType, Sets.newHashSet()));
    }

    @Test
    public void shouldSend_isFalse_whenClientDoesNotHaveOpenIdScope() {
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithoutOpenid), requestedScopesWithOpenId, nonClientCredentialsGrantType, requestedResponseTypesWithIdToken));
        assertFalse(idTokenGranter.shouldSendIdToken(null, requestedScopesWithOpenId, nonClientCredentialsGrantType, requestedResponseTypesWithIdToken));
        Collection<GrantedAuthority> clientScopesContainingNull = clientScopes(clientWithoutOpenid);
        clientScopesContainingNull.add(null);
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopesContainingNull, requestedScopesWithOpenId, nonClientCredentialsGrantType, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenResponseTypeDoesNotHaveIdToken() {
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, nonClientCredentialsGrantType, null));
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, nonClientCredentialsGrantType, Sets.newHashSet()));
        HashSet<String> setWithNull = Sets.newHashSet();
        setWithNull.add(null);
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, nonClientCredentialsGrantType, setWithNull));
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, nonClientCredentialsGrantType, requestedResponseTypesWithoutIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenSAMLBearerGrantType() {
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, GRANT_TYPE_SAML2_BEARER, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenJwtBearerGrantType() {
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, GRANT_TYPE_USER_TOKEN, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenUserTokenGrantType() {
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, GRANT_TYPE_JWT_BEARER, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenRequestGrantTypeIsClientCredentials() {
        // Can't build an id_token without an associated user account which client_credentials does not have.
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, GRANT_TYPE_CLIENT_CREDENTIALS, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isFalse_whenClientHasOpenIdScope_andNonOpenIdScopesAreRequested() {
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithoutOpenId, nonClientCredentialsGrantType, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isTrue_whenAuthorizationCodeGrantIsUsed_withCodeResponseType() {
        // This is a special case for the authorization_code code flow. Per Tian,
        // this is the only way that an id_token may be returned without the response
        // type id_token.
        assertTrue(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE, Sets.newHashSet("code")));
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), null, GRANT_TYPE_AUTHORIZATION_CODE, Sets.newHashSet("code")));
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE, Sets.newHashSet()));
        assertFalse(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, GRANT_TYPE_AUTHORIZATION_CODE, null));
    }

    @Test
    public void shouldSend_isTrue_whenClientHasOpenIdScope_andNoScopesRequested() {
        // When scopes are not explicitly requested, we default to the
        // full list of scopes configured on the client
        assertTrue(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), null, nonClientCredentialsGrantType, requestedResponseTypesWithIdToken));
        assertTrue(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), Sets.newHashSet(), nonClientCredentialsGrantType, requestedResponseTypesWithIdToken));
    }

    @Test
    public void shouldSend_isTrue_whenClientHasOpenIdScope_andOpenIdScopeIsRequested_andIdTokenResponseType() {
        // When scopes are not explicitly requested, we default to the
        // full list of scopes configured on the client
        assertTrue(idTokenGranter.shouldSendIdToken(clientScopes(clientWithOpenId), requestedScopesWithOpenId, nonClientCredentialsGrantType, requestedResponseTypesWithIdToken));
    }

    private Collection<GrantedAuthority> clientScopes(BaseClientDetails clientDetails) {
        Collection<GrantedAuthority> clientScopes;
        clientScopes = new ArrayList<>();
        for (String scope : clientDetails.getScope()) {
            clientScopes.add(new XOAuthUserAuthority(scope));
        }
        return clientScopes;
    }
}