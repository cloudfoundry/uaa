package org.cloudfoundry.identity.uaa.message;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.UaaProperties;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.login.NotificationsProperties;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.io.Serializable;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class LocalUaaRestTemplateTests {
    private LocalUaaRestTemplate localUaaRestTemplate;
    private MultitenantClientServices mockMultitenantClientServices;
    private AuthorizationServerTokenServices mockAuthorizationServerTokenServices;
    private IdentityZoneManager mockIdentityZoneManager;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        mockAuthorizationServerTokenServices = mock(AuthorizationServerTokenServices.class);
        mockMultitenantClientServices = mock(MultitenantClientServices.class);
        mockIdentityZoneManager = mock(IdentityZoneManager.class);

        localUaaRestTemplate = new LocalUaaRestTemplate(
                new UaaProperties.RootLevel(false, "loginsecret", false, 443),
                new NotificationsProperties("", false, true),
                mockAuthorizationServerTokenServices,
                mockMultitenantClientServices,
                mockIdentityZoneManager);

        ClientDetails mockClientDetails = mock(ClientDetails.class);
        when(mockClientDetails.getAuthorities()).thenReturn(Arrays.asList(
                UaaAuthority.authority("something"),
                UaaAuthority.authority("else")
        ));

        when(mockMultitenantClientServices.loadClientByClientId(any(), any())).thenReturn(mockClientDetails);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("currentIdentityZoneId");
    }

    @Test
    void acquireAccessToken() {
        OAuth2ClientContext mockOAuth2ClientContext = mock(OAuth2ClientContext.class);
        OAuth2AccessToken mockOAuth2AccessToken = mock(OAuth2AccessToken.class);
        when(mockAuthorizationServerTokenServices.createAccessToken(any())).thenReturn(mockOAuth2AccessToken);

        OAuth2AccessToken actualResult = localUaaRestTemplate.acquireAccessToken(mockOAuth2ClientContext);

        assertThat(actualResult).isEqualTo(mockOAuth2AccessToken);

        ImmutableMap<String, String> requestParameters = ImmutableMap.<String, String>builder()
                .put(OAuth2Utils.CLIENT_ID, "login")
                .put(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                .build();
        OAuth2Request request = new OAuth2Request(
                requestParameters,
                "login",
                new HashSet<>(),
                true,
                Sets.newHashSet("something", "else"),
                Sets.newHashSet(OriginKeys.UAA),
                null,
                new HashSet<>(),
                ImmutableMap.<String, Serializable>builder().build());
        OAuth2Authentication authentication = new OAuth2Authentication(request, null);

        verify(mockIdentityZoneManager).getCurrentIdentityZoneId();
        verify(mockMultitenantClientServices).loadClientByClientId("login", "currentIdentityZoneId");
        verify(mockOAuth2ClientContext).setAccessToken(mockOAuth2AccessToken);
        verify(mockAuthorizationServerTokenServices).createAccessToken(authentication);
    }
}