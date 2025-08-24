package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.user.UaaUserApprovalHandler;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collections;

import static java.util.Collections.singleton;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UaaUserApprovalHandlerTests {

    private UaaUserApprovalHandler handler;
    private AuthorizationRequest authorizationRequest;
    private Authentication userAuthentication;
    private UaaClientDetails client;

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

        client = new UaaClientDetails("client", "none", "read,write", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none");
        when(mockMultitenantClientServices.loadClientByClientId("client", currentIdentityZoneId)).thenReturn(client);
    }

    @Test
    void notAutoApprove() {
        assertThat(handler.isApproved(authorizationRequest, userAuthentication)).isFalse();
    }

    @Test
    void autoApproveAll() {
        client.setAutoApproveScopes(singleton("true"));
        assertThat(handler.isApproved(authorizationRequest, userAuthentication)).isTrue();
    }

    @Test
    void autoApproveByScopeRead() {
        client.setAutoApproveScopes(singleton("read"));
        assertThat(handler.isApproved(authorizationRequest, userAuthentication)).isTrue();
    }

    @Test
    void autoApproveByScopeWrite() {
        client.setAutoApproveScopes(singleton("write"));
        assertThat(handler.isApproved(authorizationRequest, userAuthentication)).isFalse();
    }
}
