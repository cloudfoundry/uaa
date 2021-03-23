package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.StringUtils;

import java.util.*;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;

@ExtendWith(PollutionPreventionExtension.class)
class UaaAuthorizationRequestManagerTests {

    private UaaAuthorizationRequestManager factory;

    private MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);

    private UaaUserDatabase uaaUserDatabase = mock(UaaUserDatabase.class);

    private IdentityProviderProvisioning providerProvisioning = mock(IdentityProviderProvisioning.class);

    private Map<String, String> parameters = new HashMap<String, String>();

    private BaseClientDetails client = new BaseClientDetails();

    private UaaUser user = null;

    private SecurityContextAccessor mockSecurityContextAccessor;

    @BeforeEach
    void initUaaAuthorizationRequestManagerTests() {
        mockSecurityContextAccessor = mock(SecurityContextAccessor.class);
        when(mockSecurityContextAccessor.isUser()).thenReturn(true);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn((Collection)AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz"));
        parameters.put("client_id", "foo");
        factory = new UaaAuthorizationRequestManager(clientDetailsService, mockSecurityContextAccessor, uaaUserDatabase, providerProvisioning);
        when(clientDetailsService.loadClientByClientId("foo", "uaa")).thenReturn(client);
        user = new UaaUser("testid", "testuser","","test@test.org",AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz,space.1.developer,space.2.developer,space.1.admin"),"givenname", "familyname", null, null, OriginKeys.UAA, null, true, IdentityZone.getUaaZoneId(), "testid", new Date());
        when(uaaUserDatabase.retrieveUserById(any())).thenReturn(user);
    }

    @AfterEach
    void clearZoneContext() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void testClientIDPAuthorizationInUAAzoneNoList() {
        factory.checkClientIdpAuthorization(client, user);
    }

    @Test
    void testClientIDPAuthorizationInNonUAAzoneNoList() {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("test", "test"));
        factory.checkClientIdpAuthorization(client, user);
    }

    @Test
    void testClientIDPAuthorizationInUAAzoneListSucceeds() {
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(MultitenancyFixture.identityProvider("random", "random"));
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("random"));
        factory.checkClientIdpAuthorization(client, user);
    }

    @Test
    void testClientIDPAuthorizationInUAAzoneListFails() {
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(MultitenancyFixture.identityProvider("random", "random"));
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("random2"));
        assertThrows(UnauthorizedClientException.class, () -> factory.checkClientIdpAuthorization(client, user));
    }

    @Test
    void testClientIDPAuthorizationInUAAzoneNullProvider() {
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(null);
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("random2"));
        assertThrows(UnauthorizedClientException.class, () -> factory.checkClientIdpAuthorization(client, user));
    }

    @Test
    void testClientIDPAuthorizationInUAAzoneEmptyResultSetException() {
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("random2"));
        assertThrows(UnauthorizedClientException.class, () -> factory.checkClientIdpAuthorization(client, user));
    }

    @Test
    void testTokenRequestIncludesResourceIds() {
        when(mockSecurityContextAccessor.isUser()).thenReturn(false);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn((Collection)AuthorityUtils.commaSeparatedStringToAuthorityList("aud1.test aud2.test"));
        parameters.put("scope", "aud1.test aud2.test");
        parameters.put("client_id", client.getClientId());
        parameters.put(OAuth2Utils.GRANT_TYPE, "client_credentials");
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("aud1.test"));
        client.setScope(StringUtils.commaDelimitedListToSet("aud1.test,aud2.test"));
        OAuth2Request request = factory.createTokenRequest(parameters, client).createOAuth2Request(client);
        assertEquals(StringUtils.commaDelimitedListToSet("aud1.test,aud2.test"), new TreeSet<>(request.getScope()));
        assertEquals(StringUtils.commaDelimitedListToSet("aud1,aud2"), new TreeSet<>(request.getResourceIds()));
    }

    @Test
    void test_user_token_request() {
        when(mockSecurityContextAccessor.isUser()).thenReturn(true);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn((Collection)AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.user,requested.scope"));
        BaseClientDetails recipient = new BaseClientDetails("recipient", "requested", "requested.scope", "password", "");
        parameters.put("scope", "requested.scope");
        parameters.put("client_id", recipient.getClientId());
        parameters.put("expires_in", "44000");
        parameters.put(OAuth2Utils.GRANT_TYPE, TokenConstants.GRANT_TYPE_USER_TOKEN);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("uaa.user"));
        client.setScope(StringUtils.commaDelimitedListToSet("aud1.test,aud2.test,uaa.user"));
        when(clientDetailsService.loadClientByClientId(recipient.getClientId(), "uaa")).thenReturn(recipient);
        ReflectionTestUtils.setField(factory, "uaaUserDatabase", null);
        client.setClientId("requestingId");
        OAuth2Request request = factory.createTokenRequest(parameters, client).createOAuth2Request(recipient);
        assertEquals(recipient.getClientId(), request.getClientId());
        assertEquals(recipient.getClientId(), request.getRequestParameters().get(CLIENT_ID));
        assertEquals(client.getClientId(), request.getRequestParameters().get(TokenConstants.USER_TOKEN_REQUESTING_CLIENT_ID));
        assertEquals(StringUtils.commaDelimitedListToSet("requested.scope"), new TreeSet<>(request.getScope()));
        assertEquals(StringUtils.commaDelimitedListToSet(recipient.getClientId()+",requested"), new TreeSet<>(request.getResourceIds()));
        assertEquals("44000", request.getRequestParameters().get("expires_in"));
    }

    @Test
    void testFactoryProducesSomething() {
        assertNotNull(factory.createAuthorizationRequest(parameters));
    }


    @Test
    void testScopeIncludesAuthoritiesForUser() {
        client.setScope(StringUtils.commaDelimitedListToSet("one,two,foo.bar"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet("foo.bar"), new TreeSet<String>(request.getScope()));
        factory.validateParameters(request.getRequestParameters(), client);
    }

    @Test
    void testWildcardScopesIncludesAuthoritiesForUser() {
        when(mockSecurityContextAccessor.isUser()).thenReturn(true);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn((Collection)AuthorityUtils.commaSeparatedStringToAuthorityList("space.1.developer,space.2.developer,space.1.admin"));
        client.setScope(StringUtils.commaDelimitedListToSet("space.*.developer"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet("space.1.developer,space.2.developer"), new TreeSet<String>(request.getScope()));
        factory.validateParameters(request.getRequestParameters(), client);
    }

    @Test
    void testOpenidScopeIncludeIsAResourceId() {
        parameters.put("scope", "openid foo.bar");
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("openid"));
        client.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet("openid,foo.bar"), new TreeSet<String>(request.getScope()));
        assertEquals(StringUtils.commaDelimitedListToSet("openid,foo"), new TreeSet<String>(request.getResourceIds()));
    }

    @Test
    void testEmptyScopeOkForClientWithNoScopes() {
        client.setScope(StringUtils.commaDelimitedListToSet("")); // empty
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet(""), new TreeSet<String>(request.getScope()));
    }

    @Test
    void testEmptyScopeFailsClientWithScopes() {
        client.setScope(StringUtils.commaDelimitedListToSet("one,two")); // not empty
        assertThrowsWithMessageThat(InvalidScopeException.class, () -> factory.createAuthorizationRequest(parameters), Matchers.containsString("[one, two] is invalid. This user is not allowed any of the requested scopes"));
    }

    @Test
    void testScopesValid() {
        parameters.put("scope","read");
        factory.validateParameters(parameters, new BaseClientDetails("foo", null, "read,write", "implicit", null));
    }

    @Test
    void testScopesValidWithWildcard() {
        parameters.put("scope","read write space.1.developer space.2.developer");
        factory.validateParameters(parameters, new BaseClientDetails("foo", null, "read,write,space.*.developer", "implicit", null));
    }

    @Test
    void testScopesInvValidWithWildcard() {
        parameters.put("scope","read write space.1.developer space.2.developer space.1.admin");
        assertThrowsWithMessageThat(InvalidScopeException.class,
                () -> factory.validateParameters(parameters,
                        new BaseClientDetails("foo", null, "read,write,space.*.developer", "implicit", null)),
                Matchers.containsString("space.1.admin is invalid. Please use a valid scope name in the request"));
    }

    @Test
    void testScopesInvalid() {
        parameters.put("scope", "admin");
        assertThrowsWithMessageThat(InvalidScopeException.class,
                () -> factory.validateParameters(parameters,
                        new BaseClientDetails("foo", null, "read,write", "implicit", null)),
                Matchers.containsString("admin is invalid. Please use a valid scope name in the request"));
    }

    @Test
    void testWildcardIntersect1() {
        Set<String> client = new HashSet<>(Collections.singletonList("space.*.developer"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(client, client, user);
        assertEquals(2, result.size());
        assertTrue(result.contains("space.1.developer"));
        assertTrue(result.contains("space.2.developer"));
    }

    @Test
    void testWildcardIntersect2() {
        Set<String> client = new HashSet<>(Collections.singletonList("space.*.developer"));
        Set<String> requested = new HashSet<>(Collections.singletonList("space.1.developer"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertEquals(1, result.size());
        assertTrue(result.contains("space.1.developer"));
    }

    @Test
    void testWildcardIntersect3() {
        Set<String> client = new HashSet<>(Collections.singletonList("space.*.developer"));
        Set<String> requested = new HashSet<>(Collections.singletonList("space.*.admin"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertEquals(0, result.size());
    }

    @Test
    void testWildcardIntersect4() {
        Set<String> client = new HashSet<>(Arrays.asList("space.*.developer","space.*.admin"));
        Set<String> requested = new HashSet<>(Collections.singletonList("space.*.admin"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertEquals(1, result.size());
        assertTrue(result.contains("space.1.admin"));
    }

    @Test
    void testWildcardIntersect5() {
        Set<String> client = new HashSet<>(Arrays.asList("space.*.developer","space.*.admin", "space.3.operator"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(client, client, user);
        assertEquals(4, result.size());
        assertTrue(result.contains("space.1.admin"));
        assertTrue(result.contains("space.3.operator"));
        assertTrue(result.contains("space.1.developer"));
        assertTrue(result.contains("space.2.developer"));
    }

    @Test
    void testWildcardIntersect6() {
        Set<String> client = new HashSet<>(Collections.singletonList("space.*.developer,space.*.admin"));
        Set<String> requested = new HashSet<>(Collections.singletonList("space.*.admin"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertEquals(0, result.size());
    }

}
