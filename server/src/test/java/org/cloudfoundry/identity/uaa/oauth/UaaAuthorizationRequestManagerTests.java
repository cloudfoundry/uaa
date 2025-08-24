package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnauthorizedClientException;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class UaaAuthorizationRequestManagerTests {

    private UaaAuthorizationRequestManager factory;

    private MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);

    private UaaUserDatabase uaaUserDatabase = mock(UaaUserDatabase.class);

    private IdentityProviderProvisioning providerProvisioning = mock(IdentityProviderProvisioning.class);

    private Map<String, String> parameters = new HashMap<>();

    private UaaClientDetails client = new UaaClientDetails();

    private UaaUser user;

    private SecurityContextAccessor mockSecurityContextAccessor;

    @BeforeEach
    void initUaaAuthorizationRequestManagerTests() {
        mockSecurityContextAccessor = mock(SecurityContextAccessor.class);
        when(mockSecurityContextAccessor.isUser()).thenReturn(true);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn((Collection) AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz"));
        parameters.put("client_id", "foo");
        factory = new UaaAuthorizationRequestManager(clientDetailsService, mockSecurityContextAccessor, uaaUserDatabase, providerProvisioning, new IdentityZoneManagerImpl());
        when(clientDetailsService.loadClientByClientId("foo", "uaa")).thenReturn(client);
        user = new UaaUser("testid", "testuser", "", "test@test.org", AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz,space.1.developer,space.2.developer,space.1.admin"), "givenname", "familyname", null, null, OriginKeys.UAA, null, true, IdentityZone.getUaaZoneId(), "testid", new Date());
        when(uaaUserDatabase.retrieveUserById(any())).thenReturn(user);
    }

    @AfterEach
    void clearZoneContext() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void clientIDPAuthorizationInUAAzoneNoList() {
        factory.checkClientIdpAuthorization(client, user);
    }

    @Test
    void clientIDPAuthorizationInNonUAAzoneNoList() {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("test", "test"));
        factory.checkClientIdpAuthorization(client, user);
    }

    @Test
    void clientIDPAuthorizationInUAAzoneListSucceeds() {
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(MultitenancyFixture.identityProvider("random", "random"));
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("random"));
        factory.checkClientIdpAuthorization(client, user);
    }

    @Test
    void clientIDPAuthorizationInUAAzoneListFails() {
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(MultitenancyFixture.identityProvider("random", "random"));
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("random2"));
        assertThatExceptionOfType(UnauthorizedClientException.class).isThrownBy(() -> factory.checkClientIdpAuthorization(client, user));
    }

    @Test
    void clientIDPAuthorizationInUAAzoneNullProvider() {
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(null);
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("random2"));
        assertThatExceptionOfType(UnauthorizedClientException.class).isThrownBy(() -> factory.checkClientIdpAuthorization(client, user));
    }

    @Test
    void clientIDPAuthorizationInUAAzoneEmptyResultSetException() {
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("random2"));
        assertThatExceptionOfType(UnauthorizedClientException.class).isThrownBy(() -> factory.checkClientIdpAuthorization(client, user));
    }

    @Test
    void tokenRequestIncludesResourceIds() {
        when(mockSecurityContextAccessor.isUser()).thenReturn(false);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn((Collection) AuthorityUtils.commaSeparatedStringToAuthorityList("aud1.test aud2.test"));
        parameters.put("scope", "aud1.test aud2.test");
        parameters.put("client_id", client.getClientId());
        parameters.put(OAuth2Utils.GRANT_TYPE, "client_credentials");
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("aud1.test"));
        client.setScope(StringUtils.commaDelimitedListToSet("aud1.test,aud2.test"));
        OAuth2Request request = factory.createTokenRequest(parameters, client).createOAuth2Request(client);
        assertThat(new TreeSet<>(request.getScope())).isEqualTo(StringUtils.commaDelimitedListToSet("aud1.test,aud2.test"));
        assertThat(new TreeSet<>(request.getResourceIds())).isEqualTo(StringUtils.commaDelimitedListToSet("aud1,aud2"));
    }

    @Test
    void tokenRequestEquals() {
        client.setClientId("foo");
        assertThat(factory.createTokenRequest(parameters, client).hashCode()).isNotZero();
        assertThat(factory.createTokenRequest(parameters, client)).isEqualTo(factory.createTokenRequest(parameters, client));
        factory.setScopeSeparator(".");
        factory.setScopesToResources(Map.of("aud1.test", "aud2.test"));
        assertThat(factory.createOAuth2Request(client, factory.createTokenRequest(Map.of("client_id", client.getClientId()), client))).isNotEqualTo(factory.createTokenRequest(parameters, client));
        assertThat(factory.createTokenRequest(parameters, client)).isNotEqualTo(factory.createOAuth2Request(factory.createAuthorizationRequest(Map.of("client_id", client.getClientId()))))
                .isNotEqualTo(factory.createTokenRequest(factory.createAuthorizationRequest(Map.of("client_id", client.getClientId())), ""));
    }

    @Test
    void user_token_request() {
        OAuth2Authentication oAuth2Authentication = mock(OAuth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(mockSecurityContextAccessor.isUser()).thenReturn(true);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn((Collection) AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.user,requested.scope"));
        when(oAuth2Authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(oAuth2Request.getExtensions()).thenReturn(Map.of("client_auth_method", "none"));
        SecurityContextHolder.getContext().setAuthentication(oAuth2Authentication);
        UaaClientDetails recipient = new UaaClientDetails("recipient", "requested", "requested.scope", "password", "");
        parameters.put("scope", "requested.scope");
        parameters.put("client_id", recipient.getClientId());
        parameters.put("expires_in", "44000");
        parameters.put(OAuth2Utils.GRANT_TYPE, TokenConstants.GRANT_TYPE_USER_TOKEN);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("uaa.user"));
        IdentityZoneHolder.get().getConfig().getUserConfig().setAllowedGroups(null); // all groups allowed
        client.setScope(StringUtils.commaDelimitedListToSet("aud1.test,aud2.test,uaa.user"));
        when(clientDetailsService.loadClientByClientId(recipient.getClientId(), "uaa")).thenReturn(recipient);
        ReflectionTestUtils.setField(factory, "uaaUserDatabase", null);
        client.setClientId("requestingId");
        OAuth2Request request = factory.createTokenRequest(parameters, client).createOAuth2Request(recipient);
        assertThat(request.getClientId()).isEqualTo(recipient.getClientId());
        assertThat(request.getRequestParameters()).containsEntry(CLIENT_ID, recipient.getClientId())
                .containsEntry(TokenConstants.USER_TOKEN_REQUESTING_CLIENT_ID, client.getClientId());
        assertThat(new TreeSet<>(request.getScope())).isEqualTo(StringUtils.commaDelimitedListToSet("requested.scope"));
        assertThat(new TreeSet<>(request.getResourceIds())).isEqualTo(StringUtils.commaDelimitedListToSet(recipient.getClientId() + ",requested"));
        assertThat(request.getRequestParameters()).containsEntry("expires_in", "44000");
    }

    @Test
    void factoryProducesSomething() {
        assertThat(factory.createAuthorizationRequest(parameters)).isNotNull();
    }

    @Test
    void scopeIncludesAuthoritiesForUser() {
        client.setScope(StringUtils.commaDelimitedListToSet("one,two,foo.bar"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertThat(new TreeSet<String>(request.getScope())).isEqualTo(StringUtils.commaDelimitedListToSet("foo.bar"));
        factory.validateParameters(request.getRequestParameters(), client);
    }

    @Test
    void scopesIncludesAllowedAuthoritiesForUser() {
        when(mockSecurityContextAccessor.isUser()).thenReturn(true);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn((Collection) AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz,space.1.developer"));
        IdentityZoneHolder.get().getConfig().getUserConfig().setAllowedGroups(Arrays.asList("openid", "foo.bar"));
        client.setScope(StringUtils.commaDelimitedListToSet("foo.bar,spam.baz,space.1.developer"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertThat(new TreeSet<String>(request.getScope())).isEqualTo(StringUtils.commaDelimitedListToSet("foo.bar"));
        factory.validateParameters(request.getRequestParameters(), client);
    }

    @Test
    void wildcardScopesIncludesAuthoritiesForUser() {
        when(mockSecurityContextAccessor.isUser()).thenReturn(true);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn((Collection) AuthorityUtils.commaSeparatedStringToAuthorityList("space.1.developer,space.2.developer,space.1.admin"));
        client.setScope(StringUtils.commaDelimitedListToSet("space.*.developer"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertThat(new TreeSet<String>(request.getScope())).isEqualTo(StringUtils.commaDelimitedListToSet("space.1.developer,space.2.developer"));
        factory.validateParameters(request.getRequestParameters(), client);
    }

    @Test
    void wildcardScopesIncludesAllowedAuthoritiesForUser() {
        when(mockSecurityContextAccessor.isUser()).thenReturn(true);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn((Collection) AuthorityUtils.commaSeparatedStringToAuthorityList("space.1.developer,space.2.developer,space.1.admin"));
        IdentityZoneHolder.get().getConfig().getUserConfig().setAllowedGroups(Arrays.asList("openid", "space.1.developer"));
        client.setScope(StringUtils.commaDelimitedListToSet("space.*.developer"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertThat(new TreeSet<String>(request.getScope())).isEqualTo(StringUtils.commaDelimitedListToSet("space.1.developer"));
        factory.validateParameters(request.getRequestParameters(), client);
    }

    @Test
    void openidScopeIncludeIsAResourceId() {
        parameters.put("scope", "openid foo.bar");
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("openid"));
        IdentityZoneHolder.get().getConfig().getUserConfig().setAllowedGroups(Arrays.asList("openid", "foo.bar"));
        client.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertThat(new TreeSet<String>(request.getScope())).isEqualTo(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        assertThat(new TreeSet<String>(request.getResourceIds())).isEqualTo(StringUtils.commaDelimitedListToSet("openid,foo"));
    }

    @Test
    void emptyScopeOkForClientWithNoScopes() {
        client.setScope(StringUtils.commaDelimitedListToSet("")); // empty
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertThat(new TreeSet<String>(request.getScope())).isEqualTo(StringUtils.commaDelimitedListToSet(""));
    }

    @Test
    void emptyScopeFailsClientWithScopes() {
        client.setScope(StringUtils.commaDelimitedListToSet("one,two")); // not empty
        assertThatThrownBy(() -> factory.createAuthorizationRequest(parameters))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessageContaining("[one, two] is invalid. This user is not allowed any of the requested scopes");
    }

    @Test
    void scopesValid() {
        parameters.put("scope", "read");
        factory.validateParameters(parameters, new UaaClientDetails("foo", null, "read,write", "implicit", null));
    }

    @Test
    void scopesValidWithWildcard() {
        parameters.put("scope", "read write space.1.developer space.2.developer");
        factory.validateParameters(parameters, new UaaClientDetails("foo", null, "read,write,space.*.developer", "implicit", null));
    }

    @Test
    void scopesInvValidWithWildcard() {
        parameters.put("scope", "read write space.1.developer space.2.developer space.1.admin");
        assertThatThrownBy(() -> factory.validateParameters(parameters, new UaaClientDetails("foo", null, "read,write,space.*.developer", "implicit", null)))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessageContaining("space.1.admin is invalid. Please use a valid scope name in the request");
    }

    @Test
    void scopesInvalid() {
        parameters.put("scope", "admin");
        assertThatThrownBy(() -> factory.validateParameters(parameters,
                new UaaClientDetails("foo", null, "read,write", "implicit", null)))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessageContaining("admin is invalid. Please use a valid scope name in the request");
    }

    @Test
    void wildcardIntersect1() {
        Set<String> client = new HashSet<>(Collections.singletonList("space.*.developer"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer", "space.2.developer", "space.1.admin", "space.3.operator"));

        Set<String> result = factory.intersectScopes(client, client, user);
        assertThat(result).hasSize(2)
                .contains("space.1.developer")
                .contains("space.2.developer");
    }

    @Test
    void wildcardIntersect2() {
        Set<String> client = new HashSet<>(Collections.singletonList("space.*.developer"));
        Set<String> requested = new HashSet<>(Collections.singletonList("space.1.developer"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer", "space.2.developer", "space.1.admin", "space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertThat(result).hasSize(1)
                .contains("space.1.developer");
    }

    @Test
    void wildcardIntersect3() {
        Set<String> client = new HashSet<>(Collections.singletonList("space.*.developer"));
        Set<String> requested = new HashSet<>(Collections.singletonList("space.*.admin"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer", "space.2.developer", "space.1.admin", "space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertThat(result).isEmpty();
    }

    @Test
    void wildcardIntersect4() {
        Set<String> client = new HashSet<>(Arrays.asList("space.*.developer", "space.*.admin"));
        Set<String> requested = new HashSet<>(Collections.singletonList("space.*.admin"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer", "space.2.developer", "space.1.admin", "space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertThat(result).hasSize(1)
                .contains("space.1.admin");
    }

    @Test
    void wildcardIntersect5() {
        Set<String> client = new HashSet<>(Arrays.asList("space.*.developer", "space.*.admin", "space.3.operator"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer", "space.2.developer", "space.1.admin", "space.3.operator"));

        Set<String> result = factory.intersectScopes(client, client, user);
        assertThat(result).hasSize(4)
                .contains("space.1.admin")
                .contains("space.3.operator")
                .contains("space.1.developer")
                .contains("space.2.developer");
    }

    @Test
    void wildcardIntersect6() {
        Set<String> client = new HashSet<>(Collections.singletonList("space.*.developer,space.*.admin"));
        Set<String> requested = new HashSet<>(Collections.singletonList("space.*.admin"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer", "space.2.developer", "space.1.admin", "space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertThat(result).isEmpty();
    }
}
