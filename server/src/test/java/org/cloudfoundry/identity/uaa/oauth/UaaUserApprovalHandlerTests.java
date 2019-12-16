package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.user.UaaUserApprovalHandler;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.Collections;

import static java.util.Collections.singleton;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UaaUserApprovalHandlerTests {

    private UaaUserApprovalHandler handler;
    private AuthorizationRequest authorizationRequest;
    private Authentication userAuthentication;
    private BaseClientDetails client;

    @BeforeEach
    void setUp() {
        final RandomValueStringGenerator generator = new RandomValueStringGenerator();
        final MultitenantClientServices mockMultitenantClientServices = mock(MultitenantClientServices.class);
        final AuthorizationServerTokenServices mockAuthorizationServerTokenServices = mock(AuthorizationServerTokenServices.class);
        final IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        final String currentIdentityZoneId = "currentIdentityZoneId-" + generator.generate();
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);
        handler = new UaaUserApprovalHandler(
                mockMultitenantClientServices,
                null,
                mockAuthorizationServerTokenServices,
                mockIdentityZoneManager);

        authorizationRequest = new AuthorizationRequest("client", Collections.singletonList("read"));
        userAuthentication = new UsernamePasswordAuthenticationToken("joe", "",
                AuthorityUtils.commaSeparatedStringToAuthorityList("USER"));

        client = new BaseClientDetails("client", "none", "read,write", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none");
        when(mockMultitenantClientServices.loadClientByClientId("client", currentIdentityZoneId)).thenReturn(client);
    }

    @Test
    void notAutoApprove() {
        assertFalse(handler.isApproved(authorizationRequest, userAuthentication));
    }

    @Test
    void autoApproveAll() {
        client.setAutoApproveScopes(singleton("true"));
        assertTrue(handler.isApproved(authorizationRequest, userAuthentication));
    }

    @Test
    void autoApproveByScopeRead() {
        client.setAutoApproveScopes(singleton("read"));
        assertTrue(handler.isApproved(authorizationRequest, userAuthentication));
    }

    @Test
    void autoApproveByScopeWrite() {
        client.setAutoApproveScopes(singleton("write"));
        assertFalse(handler.isApproved(authorizationRequest, userAuthentication));
    }
}
