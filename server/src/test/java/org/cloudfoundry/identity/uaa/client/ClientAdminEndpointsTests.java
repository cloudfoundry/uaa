package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.InvalidClientSecretException;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.ZoneAwareClientSecretPolicyValidator;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.ADD;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.DELETE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class ClientAdminEndpointsTests {

    private static final Set<String> SINGLE_REDIRECT_URL = Collections.singleton("http://redirect.url");

    private BaseClientDetails baseClientDetails;
    private ClientDetailsModification[] clientDetailsModifications;
    private UaaClientDetails uaaClientDetails;

    private QueryableResourceManager<ClientDetails> mockNoOpClientDetailsResourceManager;
    private SecurityContextAccessor mockSecurityContextAccessor;
    private MultitenantClientServices mockMultitenantClientServices;
    private AuthenticationManager mockAuthenticationManager;
    private ApplicationEventPublisher mockApplicationEventPublisher;

    private IdentityZone testZone;
    private ClientAdminEndpointsValidator clientDetailsValidator;
    private ClientAdminEndpoints clientAdminEndpoints;

    private static abstract class NoOpClientDetailsResourceManager implements QueryableResourceManager<ClientDetails> {
        @Override
        public ClientDetails create(ClientDetails resource, String zoneId) {
            Map<String, Object> additionalInformation = new HashMap<>(resource.getAdditionalInformation());
            additionalInformation.put("lastModified", 1463510591);

            BaseClientDetails altered = new BaseClientDetails(resource);
            altered.setAdditionalInformation(additionalInformation);

            return altered;
        }
    }

    @BeforeEach
    void setUp() {
        testZone = new IdentityZone();
        testZone.setId("testzone");
        mockSecurityContextAccessor = mock(SecurityContextAccessor.class);

        mockNoOpClientDetailsResourceManager = mock(NoOpClientDetailsResourceManager.class);
        when(mockNoOpClientDetailsResourceManager.create(any(ClientDetails.class), anyString())).thenCallRealMethod();
        mockMultitenantClientServices = mock(MultitenantClientServices.class);
        mockAuthenticationManager = mock(AuthenticationManager.class);
        final ClientSecretValidator clientSecretValidator = new ZoneAwareClientSecretPolicyValidator(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6), new IdentityZoneManagerImpl());
        clientDetailsValidator = new ClientAdminEndpointsValidator(mockSecurityContextAccessor,
                clientSecretValidator,
                mockNoOpClientDetailsResourceManager);

        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);

        clientAdminEndpoints = new ClientAdminEndpoints(
                mockSecurityContextAccessor,
                clientDetailsValidator,
                clientSecretValidator,
                mockAuthenticationManager,
                mock(ResourceMonitor.class),
                mock(ApprovalStore.class),
                mockMultitenantClientServices,
                mockNoOpClientDetailsResourceManager,
                5);

        baseClientDetails = new BaseClientDetails();
        baseClientDetails.setClientId("foo");
        baseClientDetails.setClientSecret("secret");
        baseClientDetails.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        baseClientDetails.setRegisteredRedirectUri(SINGLE_REDIRECT_URL);

        clientDetailsModifications = new ClientDetailsModification[5];
        for (int i = 0; i < clientDetailsModifications.length; i++) {
            clientDetailsModifications[i] = new ClientDetailsModification();
            clientDetailsModifications[i].setClientId("foo-" + i);
            clientDetailsModifications[i].setClientSecret("secret-" + i);
            clientDetailsModifications[i].setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
            clientDetailsModifications[i].setRegisteredRedirectUri(new HashSet(Collections.singletonList("https://foo-" + i)));
            clientDetailsModifications[i].setAccessTokenValiditySeconds(300);
        }

        uaaClientDetails = new UaaClientDetails(baseClientDetails);
        uaaClientDetails.setResourceIds(Collections.singletonList("none"));
        // refresh token is added automatically by endpoint validation
        uaaClientDetails.setAuthorizedGrantTypes(Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, "refresh_token"));
        uaaClientDetails.setScope(Collections.singletonList("uaa.none"));
        uaaClientDetails.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));

        mockApplicationEventPublisher = mock(ApplicationEventPublisher.class);
        clientAdminEndpoints.setApplicationEventPublisher(mockApplicationEventPublisher);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @Test
    void validateClientsTransferAutoApproveScopeSet() {
        List<String> scopes = Arrays.asList("scope1", "scope2");
        baseClientDetails.setAutoApproveScopes(new HashSet<>(scopes));
        ClientDetails test = clientDetailsValidator.validate(baseClientDetails, Mode.CREATE);
        for (String scope : scopes) {
            assertTrue(test.isAutoApprove(scope), "Client should have " + scope + " autoapprove.");
        }
    }

    @Test
    void statistics() {
        assertEquals(0, clientAdminEndpoints.getClientDeletes());
        assertEquals(0, clientAdminEndpoints.getClientSecretChanges());
        assertEquals(0, clientAdminEndpoints.getClientUpdates());
        assertEquals(0, clientAdminEndpoints.getErrorCounts().size());
        assertEquals(0, clientAdminEndpoints.getTotalClients());
    }

    @Test
    void createClientDetails() {
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        ClientDetails result = clientAdminEndpoints.createClientDetails(baseClientDetails);
        assertNull(result.getClientSecret());
        verify(mockNoOpClientDetailsResourceManager).create(uaaClientDetails, IdentityZoneHolder.get().getId());
        assertEquals(1463510591, result.getAdditionalInformation().get("lastModified"));
    }

    @Test
    void createClientDetails_With_Secret_Length_Less_Than_MinLength() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(7, 255, 0, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        assertThrows(InvalidClientSecretException.class, () -> clientAdminEndpoints.createClientDetails(baseClientDetails));
    }

    @Test
    void createClientDetails_With_Secret_Length_Greater_Than_MaxLength() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        assertThrows(InvalidClientSecretException.class, () -> clientAdminEndpoints.createClientDetails(baseClientDetails));
    }

    @Test
    void createClientDetails_With_Secret_Require_Digit() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 1, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        assertThrows(InvalidClientSecretException.class, () -> clientAdminEndpoints.createClientDetails(baseClientDetails));
    }

    @Test
    void createClientDetails_With_Secret_Require_Uppercase() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 1, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        assertThrows(InvalidClientSecretException.class, () -> clientAdminEndpoints.createClientDetails(baseClientDetails));
    }

    @Test
    void createClientDetails_With_Secret_Require_Lowercase() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 1, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        assertThrows(InvalidClientSecretException.class, () -> clientAdminEndpoints.createClientDetails(baseClientDetails));
    }

    @Test
    void createClientDetails_With_Secret_Require_Special_Character() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 1, 6));
        IdentityZoneHolder.set(testZone);
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        assertThrows(InvalidClientSecretException.class, () -> clientAdminEndpoints.createClientDetails(baseClientDetails));
    }

    @Test
    void createClientDetails_With_Secret_Satisfying_Complex_Policy() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(6, 255, 1, 1, 1, 1, 6));
        IdentityZoneHolder.set(testZone);
        String complexPolicySatisfyingSecret = "Secret1@";
        baseClientDetails.setClientSecret(complexPolicySatisfyingSecret);
        uaaClientDetails.setClientSecret(complexPolicySatisfyingSecret);
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        ClientDetails result = clientAdminEndpoints.createClientDetails(baseClientDetails);
        assertNull(result.getClientSecret());
        verify(mockNoOpClientDetailsResourceManager).create(uaaClientDetails, testZone.getId());
        assertEquals(1463510591, result.getAdditionalInformation().get("lastModified"));
    }

    @Test
    void getRestrictedScopesList() {
        assertEquals(new UaaScopes().getUaaScopes(), clientAdminEndpoints.getRestrictedClientScopes());
    }

    @Test
    void cannotCreateRestrictedClientSpScopes() {
        List<String> badScopes = new ArrayList<>();
        badScopes.add("sps.write");
        badScopes.add("sps.read");
        badScopes.add("zones.*.sps.read");
        badScopes.add("zones.*.sps.write");
        badScopes.add("zones.*.idps.write");
        baseClientDetails.setScope(badScopes);
        for (String scope :
                badScopes) {
            baseClientDetails.setScope(Collections.singletonList(scope));
            try {
                clientAdminEndpoints.createRestrictedClientDetails(baseClientDetails);
                fail("no error thrown for restricted scope " + scope);
            } catch (InvalidClientDetailsException e) {
                assertThat(e.getMessage(), containsString("is a restricted scope."));
            }
        }
    }

    @Test
    void cannotCreateRestrictedClientInvalidScopes() {
        baseClientDetails.setClientId("admin");
        baseClientDetails.setScope(new UaaScopes().getUaaScopes());
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createRestrictedClientDetails(baseClientDetails));
    }

    @Test
    void cannotCreateRestrictedClientInvalidAuthorities() {
        baseClientDetails.setAuthorities(new UaaScopes().getUaaAuthorities());
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createRestrictedClientDetails(baseClientDetails));
    }

    @Test
    void cannotUpdateRestrictedClientInvalidScopes() {
        baseClientDetails.setScope(new UaaScopes().getUaaScopes());
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.updateRestrictedClientDetails(baseClientDetails, baseClientDetails.getClientId()));
    }

    @Test
    void cannotUpdateRestrictedClientInvalidAuthorities() {
        baseClientDetails.setAuthorities(new UaaScopes().getUaaAuthorities());
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.updateRestrictedClientDetails(baseClientDetails, baseClientDetails.getClientId()));
    }

    @Test
    void multipleCreateClientDetailsNullArray() {
        assertThrows(NoSuchClientException.class, () -> clientAdminEndpoints.createClientDetailsTx(null));
    }

    @Test
    void multipleCreateClientDetailsEmptyArray() {
        assertThrows(NoSuchClientException.class, () -> clientAdminEndpoints.createClientDetailsTx(new ClientDetailsModification[0]));
    }

    @Test
    void multipleCreateClientDetailsNonExistent() {
        ClientDetailsModification detailsModification = new ClientDetailsModification();
        detailsModification.setClientId("unknown");
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetailsTx(new ClientDetailsModification[]{detailsModification}));
    }

    @Test
    void multipleUpdateClientDetailsNullArray() {
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.updateClientDetailsTx(null));
    }

    @Test
    void multipleUpdateClientDetailsEmptyArray() {
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.updateClientDetailsTx(new ClientDetailsModification[0]));
    }

    @Test
    void multipleCreateClientDetails() {
        ClientDetails[] results = clientAdminEndpoints.createClientDetailsTx(clientDetailsModifications);
        assertEquals(clientDetailsModifications.length, results.length, "We should have created " + clientDetailsModifications.length + " clients.");
        for (int i = 0; i < clientDetailsModifications.length; i++) {
            ClientDetails result = results[i];
            assertNull(result.getClientSecret());
        }
    }

    @Test
    void createClientDetailsWithReservedId() {
        baseClientDetails.setClientId("uaa");
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(baseClientDetails));
    }

    @Test
    void createMultipleClientDetailsWithReservedId() {
        clientDetailsModifications[clientDetailsModifications.length - 1].setClientId("uaa");
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetailsTx(clientDetailsModifications));
    }

    @Test
    void createClientDetailsWithNoGrantType() {
        baseClientDetails.setAuthorizedGrantTypes(Collections.emptySet());
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(baseClientDetails));
    }

    @Test
    void createMultipleClientDetailsWithNoGrantType() {
        clientDetailsModifications[clientDetailsModifications.length - 1].setAuthorizedGrantTypes(Collections.emptySet());
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetailsTx(clientDetailsModifications));
    }

    @Test
    void createClientDetailsWithClientCredentials() {
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        baseClientDetails.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
        uaaClientDetails.setAuthorizedGrantTypes(baseClientDetails.getAuthorizedGrantTypes());
        ClientDetails result = clientAdminEndpoints.createClientDetails(baseClientDetails);
        assertNull(result.getClientSecret());
        verify(mockNoOpClientDetailsResourceManager).create(uaaClientDetails, IdentityZoneHolder.get().getId());
    }

    @Test
    void createClientDetailsWithJwtBearer() {
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        baseClientDetails.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        baseClientDetails.setScope(Collections.singletonList(baseClientDetails.getClientId() + ".scope"));
        uaaClientDetails.setAuthorizedGrantTypes(baseClientDetails.getAuthorizedGrantTypes());
        uaaClientDetails.setScope(baseClientDetails.getScope());
        ClientDetails result = clientAdminEndpoints.createClientDetails(baseClientDetails);
        assertNull(result.getClientSecret());
        verify(mockNoOpClientDetailsResourceManager).create(uaaClientDetails, IdentityZoneHolder.get().getId());
    }

    @Test
    void createClientDetailsWithAdditionalInformation() {
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        baseClientDetails.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        uaaClientDetails.setAdditionalInformation(baseClientDetails.getAdditionalInformation());
        ClientDetails result = clientAdminEndpoints.createClientDetails(baseClientDetails);
        assertNull(result.getClientSecret());
        verify(mockNoOpClientDetailsResourceManager).create(uaaClientDetails, IdentityZoneHolder.get().getId());
    }

    @Test
    void resourceServerCreation() {
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(uaaClientDetails);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        baseClientDetails.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.resource"));
        baseClientDetails.setScope(Collections.singletonList(uaaClientDetails.getClientId() + ".some"));
        baseClientDetails.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
        clientAdminEndpoints.createClientDetails(baseClientDetails);
    }

    @Test
    void createClientDetailsWithPasswordGrant() {
        baseClientDetails.setAuthorizedGrantTypes(Collections.singletonList("password"));
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(baseClientDetails));
        verify(mockMultitenantClientServices, never()).addClientDetails(any());
    }

    @Test
    void findClientDetails() {
        when(mockNoOpClientDetailsResourceManager.query("filter", "sortBy", true, IdentityZoneHolder.get().getId())).thenReturn(
                Collections.singletonList(uaaClientDetails));
        SearchResults<?> result = clientAdminEndpoints.listClientDetails("client_id", "filter", "sortBy", "ascending", 1, 100);
        assertEquals(1, result.getResources().size());
        verify(mockNoOpClientDetailsResourceManager).query("filter", "sortBy", true, IdentityZoneHolder.get().getId());

        result = clientAdminEndpoints.listClientDetails("", "filter", "sortBy", "ascending", 1, 100);
        assertEquals(1, result.getResources().size());
    }

    @Test
    void findClientDetailsInvalidFilter() {
        when(mockNoOpClientDetailsResourceManager.query("filter", "sortBy", true, IdentityZoneHolder.get().getId())).thenThrow(new IllegalArgumentException());
        assertThrows(UaaException.class, () -> clientAdminEndpoints.listClientDetails("client_id", "filter", "sortBy", "ascending", 1, 100));
    }

    @Test
    void findClientDetails_Test_Attribute_Filter() {
        when(mockNoOpClientDetailsResourceManager.query(anyString(), anyString(), anyBoolean(), eq(IdentityZoneHolder.get().getId()))).thenReturn(Arrays.asList(clientDetailsModifications));
        for (String attribute : Arrays.asList("client_id", "resource_ids", "authorized_grant_types", "redirect_uri", "access_token_validity", "refresh_token_validity", "autoapprove", "additionalinformation")) {
            SearchResults<Map<String, Object>> result = (SearchResults<Map<String, Object>>) clientAdminEndpoints.listClientDetails(attribute, "client_id pr", "sortBy", "ascending", 1, 100);
            validateAttributeResults(result, Collections.singletonList(attribute));
        }
    }

    @Test
    void updateClientDetailsWithNullCallerAndInvalidScope() {
        when(mockNoOpClientDetailsResourceManager.retrieve(baseClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(baseClientDetails));
        baseClientDetails.setScope(Collections.singletonList("read"));
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.updateClientDetails(baseClientDetails, baseClientDetails.getClientId()));
        verify(mockMultitenantClientServices, never()).updateClientDetails(any());
    }

    @Test
    void nonExistentClient1() {
        when(mockNoOpClientDetailsResourceManager.retrieve(baseClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenThrow(new InvalidClientDetailsException(""));
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.getClientDetails(baseClientDetails.getClientId()));
    }

    @Test
    void nonExistentClient2() {
        when(mockNoOpClientDetailsResourceManager.retrieve(baseClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenThrow(new BadClientCredentialsException());
        assertThrows(NoSuchClientException.class, () -> clientAdminEndpoints.getClientDetails(baseClientDetails.getClientId()));
    }

    @Test
    void getClientDetails() {
        when(mockNoOpClientDetailsResourceManager.retrieve(baseClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(baseClientDetails);
        baseClientDetails.setScope(Collections.singletonList(baseClientDetails.getClientId() + ".read"));
        baseClientDetails.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        ClientDetails result = clientAdminEndpoints.getClientDetails(baseClientDetails.getClientId());
        assertNull(result.getClientSecret());
        assertEquals(baseClientDetails.getAdditionalInformation(), result.getAdditionalInformation());
    }

    @Test
    void updateClientDetails() {
        when(mockNoOpClientDetailsResourceManager.retrieve(baseClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(baseClientDetails));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        baseClientDetails.setScope(Collections.singletonList(baseClientDetails.getClientId() + ".read"));
        ClientDetails result = clientAdminEndpoints.updateClientDetails(baseClientDetails, baseClientDetails.getClientId());
        assertNull(result.getClientSecret());
        uaaClientDetails.setScope(Collections.singletonList(baseClientDetails.getClientId() + ".read"));
        verify(mockMultitenantClientServices).updateClientDetails(uaaClientDetails, "testzone");
    }

    @Test
    void updateClientDetailsWithAdditionalInformation() {
        when(mockNoOpClientDetailsResourceManager.retrieve(baseClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(baseClientDetails));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        baseClientDetails.setScope(Collections.singletonList(baseClientDetails.getClientId() + ".read"));
        baseClientDetails.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        ClientDetails result = clientAdminEndpoints.updateClientDetails(baseClientDetails, baseClientDetails.getClientId());
        assertNull(result.getClientSecret());
        uaaClientDetails.setScope(baseClientDetails.getScope());
        uaaClientDetails.setAdditionalInformation(baseClientDetails.getAdditionalInformation());
        verify(mockMultitenantClientServices).updateClientDetails(uaaClientDetails, "testzone");
    }

    @Test
    void updateClientDetailsRemoveAdditionalInformation() {
        baseClientDetails.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        when(mockNoOpClientDetailsResourceManager.retrieve(baseClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(baseClientDetails));
        baseClientDetails.setAdditionalInformation(Collections.emptyMap());
        ClientDetails result = clientAdminEndpoints.updateClientDetails(baseClientDetails, baseClientDetails.getClientId());
        assertNull(result.getClientSecret());
        verify(mockMultitenantClientServices).updateClientDetails(uaaClientDetails, "testzone");
    }

    @Test
    void partialUpdateClientDetails() {
        when(mockNoOpClientDetailsResourceManager.retrieve(baseClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        BaseClientDetails updated = new UaaClientDetails(uaaClientDetails);
        baseClientDetails = new BaseClientDetails();
        baseClientDetails.setClientId("foo");
        baseClientDetails.setScope(Collections.singletonList("foo.write"));
        updated.setScope(baseClientDetails.getScope());
        updated.setClientSecret(null);
        updated.setRegisteredRedirectUri(SINGLE_REDIRECT_URL);
        ClientDetails result = clientAdminEndpoints.updateClientDetails(baseClientDetails, baseClientDetails.getClientId());
        assertNull(result.getClientSecret());
        verify(mockMultitenantClientServices).updateClientDetails(updated, "testzone");
    }

    @Test
    void changeSecret() {
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(mockAuthenticationManager.authenticate(any(Authentication.class))).thenReturn(auth);

        when(mockNoOpClientDetailsResourceManager.retrieve(uaaClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(uaaClientDetails.getClientSecret());
        change.setSecret("newpassword");
        clientAdminEndpoints.changeSecret(uaaClientDetails.getClientId(), change);
        verify(mockMultitenantClientServices).updateClientSecret(uaaClientDetails.getClientId(), "newpassword", "testzone");

    }

    @Test
    void addSecret() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        when(mockNoOpClientDetailsResourceManager.retrieve(uaaClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setChangeMode(ADD);

        clientAdminEndpoints.changeSecret(uaaClientDetails.getClientId(), change);
        verify(mockMultitenantClientServices).addClientSecret(uaaClientDetails.getClientId(), "newpassword", IdentityZoneHolder.get().getId());
    }

    @Test
    void addingThirdSecretForClient() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        uaaClientDetails.setClientSecret("hash1 hash2");
        when(mockNoOpClientDetailsResourceManager.retrieve(uaaClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setOldSecret("hash1");
        change.setChangeMode(ADD);
        assertThrowsWithMessageThat(InvalidClientDetailsException.class, () -> clientAdminEndpoints.changeSecret(uaaClientDetails.getClientId(), change), is("client secret is either empty or client already has two secrets."));
    }

    @Test
    void deleteSecret() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        uaaClientDetails.setClientSecret("hash1 hash2");
        when(mockNoOpClientDetailsResourceManager.retrieve(uaaClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);
        SecretChangeRequest change = new SecretChangeRequest();
        change.setChangeMode(DELETE);

        clientAdminEndpoints.changeSecret(uaaClientDetails.getClientId(), change);
        verify(mockMultitenantClientServices).deleteClientSecret(uaaClientDetails.getClientId(), IdentityZoneHolder.get().getId());
    }

    @Test
    void deleteSecretWhenOnlyOneSecret() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        uaaClientDetails.setClientSecret("hash1");
        when(mockNoOpClientDetailsResourceManager.retrieve(uaaClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);
        SecretChangeRequest change = new SecretChangeRequest();
        change.setChangeMode(DELETE);

        assertThrowsWithMessageThat(InvalidClientDetailsException.class, () -> clientAdminEndpoints.changeSecret(uaaClientDetails.getClientId(), change), is("client secret is either empty or client has only one secret."));
    }

    @Test
    void changeSecretDeniedForNonAdmin() {

        when(mockNoOpClientDetailsResourceManager.retrieve(uaaClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);

        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        assertThrowsWithMessageThat(InvalidClientDetailsException.class, () -> clientAdminEndpoints.changeSecret(uaaClientDetails.getClientId(), change), is("Bad request. Not permitted to change another client's secret"));

    }

    @Test
    void addSecretDeniedForNonAdmin() {

        when(mockNoOpClientDetailsResourceManager.retrieve(uaaClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);

        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setChangeMode(ADD);
        assertThrowsWithMessageThat(InvalidClientDetailsException.class, () -> clientAdminEndpoints.changeSecret(uaaClientDetails.getClientId(), change), is("Bad request. Not permitted to change another client's secret"));
    }

    @Test
    void changeSecretDeniedWhenOldSecretNotProvided() {

        when(mockNoOpClientDetailsResourceManager.retrieve(uaaClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);


        when(mockAuthenticationManager.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));


        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        assertThrowsWithMessageThat(InvalidClientDetailsException.class, () -> clientAdminEndpoints.changeSecret(uaaClientDetails.getClientId(), change), is("Previous secret is required and must be valid"));

    }

    @Test
    void changeSecretByAdmin() {

        when(mockNoOpClientDetailsResourceManager.retrieve(uaaClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);

        when(mockSecurityContextAccessor.getClientId()).thenReturn("admin");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(uaaClientDetails.getClientSecret());
        change.setSecret("newpassword");
        clientAdminEndpoints.changeSecret(uaaClientDetails.getClientId(), change);
        verify(mockMultitenantClientServices).updateClientSecret(uaaClientDetails.getClientId(), "newpassword", "testzone");

    }

    @Test
    void changeSecretDeniedTooLong() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 0, 6));
        String complexPolicySatisfyingSecret = "Secret1@";

        when(mockNoOpClientDetailsResourceManager.retrieve(uaaClientDetails.getClientId(), testZone.getId())).thenReturn(uaaClientDetails);

        when(mockSecurityContextAccessor.getClientId()).thenReturn("admin");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(uaaClientDetails.getClientSecret());
        change.setSecret(complexPolicySatisfyingSecret);
        assertThrows(InvalidClientSecretException.class, () -> clientAdminEndpoints.changeSecret(uaaClientDetails.getClientId(), change));
    }

    @Test
    void removeClientDetailsAdminCaller() {
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);
        when(mockNoOpClientDetailsResourceManager.retrieve("foo", IdentityZoneHolder.get().getId())).thenReturn(uaaClientDetails);
        ClientDetails result = clientAdminEndpoints.removeClientDetails("foo");
        assertNull(result.getClientSecret());
        ArgumentCaptor<EntityDeletedEvent> captor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(mockApplicationEventPublisher).publishEvent(captor.capture());
        assertNotNull(captor.getValue());
        Object deleted = captor.getValue().getDeleted();
        assertNotNull(deleted);
        assertTrue(deleted instanceof ClientDetails);
        assertEquals("foo", ((ClientDetails) deleted).getClientId());
    }

    @Test
    void scopeIsRestrictedByCaller() {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
                "uaa.none");
        when(mockNoOpClientDetailsResourceManager.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        uaaClientDetails.setScope(Collections.singletonList("some"));
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(uaaClientDetails));
    }

    @Test
    void validScopeIsNotRestrictedByCaller() {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
                "uaa.none");
        when(mockNoOpClientDetailsResourceManager.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        uaaClientDetails.setScope(Collections.singletonList("none"));
        clientAdminEndpoints.createClientDetails(uaaClientDetails);
    }

    @Test
    void clientEndpointCannotBeConfiguredWithAnInvalidMaxCount() {
        assertThrowsWithMessageThat(IllegalArgumentException.class,
                () -> new ClientAdminEndpoints(null, null, null, null, null, null, null, null, 0),
                is("Invalid \"clientMaxCount\" value (got 0). Should be positive number.")
        );
    }

    @Test
    void authorityIsRestrictedByCaller() {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
                "uaa.none");
        when(mockNoOpClientDetailsResourceManager.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        uaaClientDetails.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.some"));
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(uaaClientDetails));
    }

    @Test
    void authorityAllowedByCaller() {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "uaa.none", "client_credentials,implicit",
                "uaa.none");
        when(mockNoOpClientDetailsResourceManager.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        uaaClientDetails.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        clientAdminEndpoints.createClientDetails(uaaClientDetails);
    }

    @Test
    void cannotExpandScope() {
        BaseClientDetails caller = new BaseClientDetails();
        caller.setScope(Collections.singletonList("none"));
        when(mockNoOpClientDetailsResourceManager.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        uaaClientDetails.setAuthorizedGrantTypes(Collections.singletonList("implicit"));
        uaaClientDetails.setClientSecret("hello");
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(uaaClientDetails));
    }

    @Test
    void implicitClientWithNonEmptySecretIsRejected() {
        uaaClientDetails.setAuthorizedGrantTypes(Collections.singletonList("implicit"));
        uaaClientDetails.setClientSecret("hello");
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(uaaClientDetails));
    }

    @Test
    void implicitAndAuthorizationCodeClientIsRejected() {
        uaaClientDetails.setAuthorizedGrantTypes(Arrays.asList("implicit", GRANT_TYPE_AUTHORIZATION_CODE));
        uaaClientDetails.setClientSecret("hello");
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(uaaClientDetails));
    }

    @Test
    void implicitAndAuthorizationCodeClientIsRejectedWithNullPassword() {
        uaaClientDetails.setAuthorizedGrantTypes(Arrays.asList("implicit", GRANT_TYPE_AUTHORIZATION_CODE));
        uaaClientDetails.setClientSecret(null);
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(uaaClientDetails));
    }

    @Test
    void implicitAndAuthorizationCodeClientIsRejectedForAdmin() {
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);
        uaaClientDetails.setAuthorizedGrantTypes(Arrays.asList("implicit", GRANT_TYPE_AUTHORIZATION_CODE));
        uaaClientDetails.setClientSecret("hello");
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(uaaClientDetails));
    }

    @Test
    void nonImplicitClientWithEmptySecretIsRejected() {
        uaaClientDetails.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        uaaClientDetails.setClientSecret("");
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(uaaClientDetails));
    }

    @Test
    void updateNonImplicitClientWithEmptySecretIsOk() {
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);
        uaaClientDetails.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        uaaClientDetails.setClientSecret(null);
        clientAdminEndpoints.updateClientDetails(uaaClientDetails, uaaClientDetails.getClientId());
    }

    @Test
    void updateNonImplicitClientAndMakeItImplicit() {
        assertFalse(uaaClientDetails.getAuthorizedGrantTypes().contains("implicit"));
        uaaClientDetails.setAuthorizedGrantTypes(Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, "implicit"));
        uaaClientDetails.setClientSecret(null);
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.updateClientDetails(uaaClientDetails, uaaClientDetails.getClientId()));
    }

    @Test
    void invalidGrantTypeIsRejected() {
        uaaClientDetails.setAuthorizedGrantTypes(Collections.singletonList("not_a_grant_type"));
        assertThrows(InvalidClientDetailsException.class, () -> clientAdminEndpoints.createClientDetails(uaaClientDetails));
    }

    @Test
    void handleNoSuchClient() {
        ResponseEntity<Void> result = clientAdminEndpoints.handleNoSuchClient(new NoSuchClientException("No such client: foo"));
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }

    @Test
    void handleClientAlreadyExists() {
        ResponseEntity<InvalidClientDetailsException> result = clientAdminEndpoints
                .handleClientAlreadyExists(new ClientAlreadyExistsException("No such client: foo"));
        assertEquals(HttpStatus.CONFLICT, result.getStatusCode());
    }

    @Test
    void errorHandler() {
        ResponseEntity<InvalidClientDetailsException> result = clientAdminEndpoints
                .handleInvalidClientDetails(new InvalidClientDetailsException("No such client: foo"));
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals(1, clientAdminEndpoints.getErrorCounts().size());
    }

    @Test
    void createClientWithAutoapproveScopesList() {
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("foo.read");
        baseClientDetails.setScope(scopes);
        uaaClientDetails.setScope(scopes);
        baseClientDetails.setAutoApproveScopes(autoApproveScopes);
        uaaClientDetails.setAutoApproveScopes(autoApproveScopes);
        uaaClientDetails.setAuthorizedGrantTypes(baseClientDetails.getAuthorizedGrantTypes());
        ClientDetails result = clientAdminEndpoints.createClientDetails(baseClientDetails);
        assertNull(result.getClientSecret());
        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        verify(mockNoOpClientDetailsResourceManager).create(clientCaptor.capture(), anyString());
        BaseClientDetails created = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, created.getAutoApproveScopes());
        assertTrue(created.isAutoApprove("foo.read"));
        assertFalse(created.isAutoApprove("foo.write"));
    }

    @Test
    void createClientWithAutoapproveScopesTrue() {
        when(mockNoOpClientDetailsResourceManager.retrieve(anyString(), anyString())).thenReturn(baseClientDetails);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("true");
        baseClientDetails.setScope(scopes);
        uaaClientDetails.setScope(scopes);
        baseClientDetails.setAutoApproveScopes(autoApproveScopes);
        uaaClientDetails.setAutoApproveScopes(autoApproveScopes);
        uaaClientDetails.setAuthorizedGrantTypes(baseClientDetails.getAuthorizedGrantTypes());
        ClientDetails result = clientAdminEndpoints.createClientDetails(baseClientDetails);
        assertNull(result.getClientSecret());
        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        verify(mockNoOpClientDetailsResourceManager).create(clientCaptor.capture(), anyString());
        BaseClientDetails created = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, created.getAutoApproveScopes());
        assertTrue(created.isAutoApprove("foo.read"));
        assertTrue(created.isAutoApprove("foo.write"));
    }

    @Test
    void updateClientWithAutoapproveScopesList() {
        when(mockNoOpClientDetailsResourceManager.retrieve(baseClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(baseClientDetails));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("foo.read");

        baseClientDetails.setScope(scopes);
        uaaClientDetails.setScope(scopes);
        uaaClientDetails.setAutoApproveScopes(autoApproveScopes);

        ClientDetails result = clientAdminEndpoints.updateClientDetails(uaaClientDetails, baseClientDetails.getClientId());
        assertNull(result.getClientSecret());
        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        verify(mockMultitenantClientServices).updateClientDetails(clientCaptor.capture(), anyString());
        BaseClientDetails updated = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, updated.getAutoApproveScopes());
        assertTrue(updated.isAutoApprove("foo.read"));
        assertFalse(updated.isAutoApprove("foo.write"));
    }

    @Test
    void updateClientWithAutoapproveScopesTrue() {
        when(mockNoOpClientDetailsResourceManager.retrieve(baseClientDetails.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(baseClientDetails));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(uaaClientDetails.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("true");

        baseClientDetails.setScope(scopes);
        uaaClientDetails.setScope(scopes);
        uaaClientDetails.setAutoApproveScopes(autoApproveScopes);

        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        ClientDetails result = clientAdminEndpoints.updateClientDetails(uaaClientDetails, baseClientDetails.getClientId());
        assertNull(result.getClientSecret());
        verify(mockMultitenantClientServices).updateClientDetails(clientCaptor.capture(), anyString());
        BaseClientDetails updated = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, updated.getAutoApproveScopes());
        assertTrue(updated.isAutoApprove("foo.read"));
        assertTrue(updated.isAutoApprove("foo.write"));
    }

    private static void validateAttributeResults(SearchResults<Map<String, Object>> result, List<String> attributes) {
        assertEquals(5, result.getResources().size());
        for (String s : attributes) {
            result.getResources().forEach((map) ->
                    assertTrue(map.containsKey(s), "Expecting attribute " + s + " to be present")
            );
        }
    }

    private static void assertSetEquals(Collection<?> a, Collection<?> b) {
        assertTrue(a == null && b == null || a != null && b != null && a.containsAll(b) && b.containsAll(a), "expected " + a + " but was " + b);
    }

}
