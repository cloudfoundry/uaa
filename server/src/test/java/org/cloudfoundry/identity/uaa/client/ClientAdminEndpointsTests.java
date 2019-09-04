package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEvent;
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

import java.util.*;

import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.ADD;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.DELETE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(PollutionPreventionExtension.class)
class ClientAdminEndpointsTests {

    private ClientAdminEndpoints endpoints = null;

    private BaseClientDetails input = null;

    private ClientDetailsModification[] inputs = new ClientDetailsModification[5];

    private BaseClientDetails detail = null;

    private BaseClientDetails[] details = new BaseClientDetails[inputs.length];


    private QueryableResourceManager<ClientDetails> clientDetailsService = null;

    private SecurityContextAccessor mockSecurityContextAccessor;

    private MultitenantClientServices clientRegistrationService = null;

    private AuthenticationManager authenticationManager = null;

    private ClientAdminEndpointsValidator clientDetailsValidator = null;

    private static final Set<String> SINGLE_REDIRECT_URL = Collections.singleton("http://redirect.url");

    private IdentityZone testZone = new IdentityZone();

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
    void setUp() throws Exception {
        testZone.setId("testzone");
        mockSecurityContextAccessor = Mockito.mock(SecurityContextAccessor.class);
        endpoints = spy(new ClientAdminEndpoints(mockSecurityContextAccessor));

        clientDetailsService = Mockito.mock(NoOpClientDetailsResourceManager.class);
        when(clientDetailsService.create(any(ClientDetails.class), anyString())).thenCallRealMethod();
        ResourceMonitor clientDetailsResourceMonitor = mock(ResourceMonitor.class);
        clientRegistrationService = Mockito.mock(MultitenantClientServices.class, withSettings().extraInterfaces(SystemDeletable.class));
        authenticationManager = Mockito.mock(AuthenticationManager.class);
        ApprovalStore approvalStore = mock(ApprovalStore.class);
        clientDetailsValidator = new ClientAdminEndpointsValidator(mockSecurityContextAccessor);
        clientDetailsValidator.setClientDetailsService(clientDetailsService);
        clientDetailsValidator.setClientSecretValidator(
                new ZoneAwareClientSecretPolicyValidator(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6)));

        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);

        endpoints.setClientMaxCount(5);
        endpoints.setClientDetailsService(clientDetailsService);
        endpoints.setClientRegistrationService(clientRegistrationService);
        endpoints.setAuthenticationManager(authenticationManager);
        endpoints.setApprovalStore(approvalStore);
        endpoints.setClientDetailsValidator(clientDetailsValidator);
        endpoints.setRestrictedScopesValidator(new RestrictUaaScopesClientValidator(new UaaScopes()));
        endpoints.setClientDetailsResourceMonitor(clientDetailsResourceMonitor);

        Map<String, String> attributeNameMap = new HashMap<>();
        attributeNameMap.put("client_id", "clientId");
        attributeNameMap.put("resource_ids", "resourceIds");
        attributeNameMap.put("authorized_grant_types", "authorizedGrantTypes");
        attributeNameMap.put("redirect_uri", "registeredRedirectUri");
        attributeNameMap.put("access_token_validity", "accessTokenValiditySeconds");
        attributeNameMap.put("refresh_token_validity", "refreshTokenValiditySeconds");
        attributeNameMap.put("autoapprove", "autoApproveScopes");
        attributeNameMap.put("additionalinformation", "additionalInformation");
        endpoints.setAttributeNameMapper(new SimpleAttributeNameMapper(attributeNameMap));

        input = new BaseClientDetails();
        input.setClientId("foo");
        input.setClientSecret("secret");
        input.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        input.setRegisteredRedirectUri(SINGLE_REDIRECT_URL);

        for (int i = 0; i < inputs.length; i++) {
            inputs[i] = new ClientDetailsModification();
            inputs[i].setClientId("foo-" + i);
            inputs[i].setClientSecret("secret-" + i);
            inputs[i].setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
            inputs[i].setRegisteredRedirectUri(new HashSet(Collections.singletonList("https://foo-" + i)));
            inputs[i].setAccessTokenValiditySeconds(300);
        }

        detail = new UaaClientDetails(input);
        detail.setResourceIds(Collections.singletonList("none"));
        // refresh token is added automatically by endpoint validation
        detail.setAuthorizedGrantTypes(Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, "refresh_token"));
        detail.setScope(Collections.singletonList("uaa.none"));
        detail.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));

        for (int i = 0; i < details.length; i++) {
            details[i] = new BaseClientDetails(inputs[i]);
            details[i].setResourceIds(Collections.singletonList("none"));
            // refresh token is added automatically by endpoint validation
            details[i].setAuthorizedGrantTypes(Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, "refresh_token"));
            details[i].setScope(Collections.singletonList("uaa.none"));
            details[i].setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        }

        endpoints.setApplicationEventPublisher(
                new ApplicationEventPublisher() {
                    @Override
                    public void publishEvent(ApplicationEvent event) {
                        if (event instanceof EntityDeletedEvent) {
                            ClientDetails client = (ClientDetails) ((EntityDeletedEvent) event).getDeleted();
                            clientRegistrationService.removeClientDetails(client.getClientId());
                        }
                    }

                    @Override
                    public void publishEvent(Object event) {
                    }
                }
        );
        endpoints.afterPropertiesSet();
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @Test
    void testValidateClientsTransferAutoApproveScopeSet() {
        List<String> scopes = Arrays.asList("scope1", "scope2");
        input.setAutoApproveScopes(new HashSet<>(scopes));
        ClientDetails test = endpoints.getClientDetailsValidator().validate(input, Mode.CREATE);
        for (String scope : scopes) {
            assertTrue("Client should have " + scope + " autoapprove.", test.isAutoApprove(scope));
        }
    }

    @Test
    void testAccessors() {
        ApprovalStore as = mock(ApprovalStore.class);
        endpoints.setApprovalStore(as);
        assertSame(as, endpoints.getApprovalStore());
    }

    @Test
    void testNoApprovalStore() {
        endpoints.setApprovalStore(null);
        assertThrows(UnsupportedOperationException.class, () -> endpoints.deleteApprovals("someclient"));
    }

    @Test
    void testStatistics() {
        assertEquals(0, endpoints.getClientDeletes());
        assertEquals(0, endpoints.getClientSecretChanges());
        assertEquals(0, endpoints.getClientUpdates());
        assertEquals(0, endpoints.getErrorCounts().size());
        assertEquals(0, endpoints.getTotalClients());
    }

    @Test
    void testCreateClientDetails() throws Exception {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        verify(clientDetailsService).create(detail, IdentityZoneHolder.get().getId());
        assertEquals(1463510591, result.getAdditionalInformation().get("lastModified"));
    }

    @Test
    void testCreateClientDetails_With_Secret_Length_Less_Than_MinLength() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(7, 255, 0, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThrows(InvalidClientSecretException.class, () -> endpoints.createClientDetails(input));
    }

    @Test
    void testCreateClientDetails_With_Secret_Length_Greater_Than_MaxLength() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThrows(InvalidClientSecretException.class, () -> endpoints.createClientDetails(input));
    }

    @Test
    void testCreateClientDetails_With_Secret_Require_Digit() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 1, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThrows(InvalidClientSecretException.class, () -> endpoints.createClientDetails(input));
    }

    @Test
    void testCreateClientDetails_With_Secret_Require_Uppercase() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 1, 0, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThrows(InvalidClientSecretException.class, () -> endpoints.createClientDetails(input));
    }

    @Test
    void testCreateClientDetails_With_Secret_Require_Lowercase() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 1, 0, 0, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThrows(InvalidClientSecretException.class, () -> endpoints.createClientDetails(input));
    }

    @Test
    void testCreateClientDetails_With_Secret_Require_Special_Character() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 1, 6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        assertThrows(InvalidClientSecretException.class, () -> endpoints.createClientDetails(input));
    }

    @Test
    void testCreateClientDetails_With_Secret_Satisfying_Complex_Policy() throws Exception {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(6, 255, 1, 1, 1, 1, 6));
        IdentityZoneHolder.set(testZone);
        String complexPolicySatisfyingSecret = "Secret1@";
        input.setClientSecret(complexPolicySatisfyingSecret);
        detail.setClientSecret(complexPolicySatisfyingSecret);
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        verify(clientDetailsService).create(detail, testZone.getId());
        assertEquals(1463510591, result.getAdditionalInformation().get("lastModified"));
    }

    @Test
    void test_Get_Restricted_Scopes_List() throws Exception {
        assertEquals(new UaaScopes().getUaaScopes(), endpoints.getRestrictedClientScopes());
        endpoints.setRestrictedScopesValidator(null);
        assertNull(endpoints.getRestrictedClientScopes());
    }

    @Test
    void testCannot_Create_Restricted_Client_Sp_Scopes() throws Exception {
        List<String> badScopes = new ArrayList<>();
        badScopes.add("sps.write");
        badScopes.add("sps.read");
        badScopes.add("zones.*.sps.read");
        badScopes.add("zones.*.sps.write");
        badScopes.add("zones.*.idps.write");
        input.setScope(badScopes);
        for (String scope :
                badScopes) {
            input.setScope(Collections.singletonList(scope));
            try {
                endpoints.createRestrictedClientDetails(input);
                fail("no error thrown for restricted scope " + scope);
            } catch (InvalidClientDetailsException e) {
                assertThat(e.getMessage(), containsString("is a restricted scope."));
            }
        }
    }

    @Test
    void testCannot_Create_Restricted_Client_Invalid_Scopes() {
        input.setClientId("admin");
        input.setScope(new UaaScopes().getUaaScopes());
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createRestrictedClientDetails(input));
    }

    @Test
    void testCannot_Create_Restricted_Client_Invalid_Authorities() {
        input.setAuthorities(new UaaScopes().getUaaAuthorities());
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createRestrictedClientDetails(input));
    }

    @Test
    void testCannot_Update_Restricted_Client_Invalid_Scopes() {
        input.setScope(new UaaScopes().getUaaScopes());
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.updateRestrictedClientDetails(input, input.getClientId()));
    }

    @Test
    void testCannot_Update_Restricted_Client_Invalid_Authorities() {
        input.setAuthorities(new UaaScopes().getUaaAuthorities());
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.updateRestrictedClientDetails(input, input.getClientId()));
    }

    @Test
    void testMultipleCreateClientDetailsNullArray() {
        assertThrows(NoSuchClientException.class, () -> endpoints.createClientDetailsTx(null));
    }

    @Test
    void testMultipleCreateClientDetailsEmptyArray() {
        assertThrows(NoSuchClientException.class, () -> endpoints.createClientDetailsTx(new ClientDetailsModification[0]));
    }

    @Test
    void testMultipleCreateClientDetailsNonExistent() {
        ClientDetailsModification detailsModification = new ClientDetailsModification();
        detailsModification.setClientId("unknown");
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetailsTx(new ClientDetailsModification[]{detailsModification}));
    }

    @Test
    void testMultipleUpdateClientDetailsNullArray() {
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.updateClientDetailsTx(null));
    }

    @Test
    void testMultipleUpdateClientDetailsEmptyArray() {
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.updateClientDetailsTx(new ClientDetailsModification[0]));
    }


    @Test
    void testMultipleCreateClientDetails() throws Exception {
        ClientDetails[] results = endpoints.createClientDetailsTx(inputs);
        assertEquals("We should have created " + inputs.length + " clients.", inputs.length, results.length);
        for (int i = 0; i < inputs.length; i++) {
            ClientDetails result = results[i];
            assertNull(result.getClientSecret());
        }
    }

    @Test
    void testCreateClientDetailsWithReservedId() {
        input.setClientId("uaa");
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(input));
    }

    @Test
    void testCreateMultipleClientDetailsWithReservedId() {
        inputs[inputs.length - 1].setClientId("uaa");
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetailsTx(inputs));
    }


    @Test
    void testCreateClientDetailsWithNoGrantType() {
        input.setAuthorizedGrantTypes(Collections.emptySet());
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(input));
    }

    @Test
    void testCreateMultipleClientDetailsWithNoGrantType() {
        inputs[inputs.length - 1].setAuthorizedGrantTypes(Collections.emptySet());
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetailsTx(inputs));
    }


    @Test
    void testCreateClientDetailsWithClientCredentials() throws Exception {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        input.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        verify(clientDetailsService).create(detail, IdentityZoneHolder.get().getId());
    }

    @Test
    void testCreateClientDetailsWithJwtBearer() throws Exception {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        input.setScope(Collections.singletonList(input.getClientId() + ".scope"));
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        detail.setScope(input.getScope());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        verify(clientDetailsService).create(detail, IdentityZoneHolder.get().getId());
    }

    @Test
    void testCreateClientDetailsWithAdditionalInformation() throws Exception {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        detail.setAdditionalInformation(input.getAdditionalInformation());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        verify(clientDetailsService).create(detail, IdentityZoneHolder.get().getId());
    }

    @Test
    void testResourceServerCreation() throws Exception {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(detail);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.resource"));
        input.setScope(Collections.singletonList(detail.getClientId() + ".some"));
        input.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
        endpoints.createClientDetails(input);
    }

    @Test
    void testCreateClientDetailsWithPasswordGrant() {
        input.setAuthorizedGrantTypes(Collections.singletonList("password"));
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(input));
        verify(clientRegistrationService, never()).addClientDetails(any());
    }

    @Test
    void testFindClientDetails() throws Exception {
        Mockito.when(clientDetailsService.query("filter", "sortBy", true, IdentityZoneHolder.get().getId())).thenReturn(
                Collections.singletonList(detail));
        SearchResults<?> result = endpoints.listClientDetails("client_id", "filter", "sortBy", "ascending", 1, 100);
        assertEquals(1, result.getResources().size());
        verify(clientDetailsService).query("filter", "sortBy", true, IdentityZoneHolder.get().getId());

        result = endpoints.listClientDetails("", "filter", "sortBy", "ascending", 1, 100);
        assertEquals(1, result.getResources().size());
    }

    @Test
    void testFindClientDetailsInvalidFilter() {
        Mockito.when(clientDetailsService.query("filter", "sortBy", true, IdentityZoneHolder.get().getId())).thenThrow(new IllegalArgumentException());
        assertThrows(UaaException.class, () -> endpoints.listClientDetails("client_id", "filter", "sortBy", "ascending", 1, 100));
    }

    @Test
    void testFindClientDetails_Test_Attribute_Filter() throws Exception {
        when(clientDetailsService.query(anyString(), anyString(), anyBoolean(), eq(IdentityZoneHolder.get().getId()))).thenReturn(Arrays.asList(inputs));
        for (String attribute : Arrays.asList("client_id", "resource_ids", "authorized_grant_types", "redirect_uri", "access_token_validity", "refresh_token_validity", "autoapprove", "additionalinformation")) {
            SearchResults<Map<String, Object>> result = (SearchResults<Map<String, Object>>) endpoints.listClientDetails(attribute, "client_id pr", "sortBy", "ascending", 1, 100);
            validateAttributeResults(result, Collections.singletonList(attribute));
        }


    }

    private void validateAttributeResults(SearchResults<Map<String, Object>> result, List<String> attributes) {
        assertEquals(5, result.getResources().size());
        for (String s : attributes) {
            result.getResources().forEach((map) ->
                    assertTrue("Expecting attribute " + s + " to be present", map.containsKey(s))
            );
        }
    }

    @Test
    void testUpdateClientDetailsWithNullCallerAndInvalidScope() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(input));
        input.setScope(Collections.singletonList("read"));
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.updateClientDetails(input, input.getClientId()));
        verify(clientRegistrationService, never()).updateClientDetails(any());
    }

    @Test
    void testNonExistentClient1() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenThrow(new InvalidClientDetailsException(""));
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.getClientDetails(input.getClientId()));
    }

    @Test
    void testNonExistentClient2() {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenThrow(new BadClientCredentialsException());
        assertThrows(NoSuchClientException.class, () -> endpoints.getClientDetails(input.getClientId()));
    }

    @Test
    void testGetClientDetails() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(input);
        input.setScope(Collections.singletonList(input.getClientId() + ".read"));
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        ClientDetails result = endpoints.getClientDetails(input.getClientId());
        assertNull(result.getClientSecret());
        assertEquals(input.getAdditionalInformation(), result.getAdditionalInformation());
    }

    @Test
    void testUpdateClientDetails() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(input));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setScope(Collections.singletonList(input.getClientId() + ".read"));
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        detail.setScope(Collections.singletonList(input.getClientId() + ".read"));
        verify(clientRegistrationService).updateClientDetails(detail, "testzone");
    }

    @Test
    void testUpdateClientDetailsWithAdditionalInformation() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(input));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        input.setScope(Collections.singletonList(input.getClientId() + ".read"));
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        detail.setScope(input.getScope());
        detail.setAdditionalInformation(input.getAdditionalInformation());
        verify(clientRegistrationService).updateClientDetails(detail, "testzone");
    }

    @Test
    void testUpdateClientDetailsRemoveAdditionalInformation() throws Exception {
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(input));
        input.setAdditionalInformation(Collections.emptyMap());
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        verify(clientRegistrationService).updateClientDetails(detail, "testzone");
    }

    @Test
    void testPartialUpdateClientDetails() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        BaseClientDetails updated = new UaaClientDetails(detail);
        input = new BaseClientDetails();
        input.setClientId("foo");
        input.setScope(Collections.singletonList("foo.write"));
        updated.setScope(input.getScope());
        updated.setClientSecret(null);
        updated.setRegisteredRedirectUri(SINGLE_REDIRECT_URL);
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        verify(clientRegistrationService).updateClientDetails(updated, "testzone");
    }

    @Test
    void testChangeSecret() {
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(auth);

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(detail.getClientSecret());
        change.setSecret("newpassword");
        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).updateClientSecret(detail.getClientId(), "newpassword", "testzone");

    }

    @Test
    void testAddSecret() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setChangeMode(ADD);

        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).addClientSecret(detail.getClientId(), "newpassword", IdentityZoneHolder.get().getId());
    }

    @Test
    void testAddingThirdSecretForClient() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        detail.setClientSecret("hash1 hash2");
        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setOldSecret("hash1");
        change.setChangeMode(ADD);
        assertThrowsWithMessageThat(InvalidClientDetailsException.class, () -> endpoints.changeSecret(detail.getClientId(), change), is("client secret is either empty or client already has two secrets."));
    }

    @Test
    void testDeleteSecret() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        detail.setClientSecret("hash1 hash2");
        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);
        SecretChangeRequest change = new SecretChangeRequest();
        change.setChangeMode(DELETE);

        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).deleteClientSecret(detail.getClientId(), IdentityZoneHolder.get().getId());
    }

    @Test
    void testDeleteSecretWhenOnlyOneSecret() {
        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        detail.setClientSecret("hash1");
        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);
        SecretChangeRequest change = new SecretChangeRequest();
        change.setChangeMode(DELETE);

        assertThrowsWithMessageThat(InvalidClientDetailsException.class, () -> endpoints.changeSecret(detail.getClientId(), change), is("client secret is either empty or client has only one secret."));
    }

    @Test
    void testChangeSecretDeniedForNonAdmin() {

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);

        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        assertThrowsWithMessageThat(InvalidClientDetailsException.class, () -> endpoints.changeSecret(detail.getClientId(), change), is("Bad request. Not permitted to change another client's secret"));

    }

    @Test
    void testAddSecretDeniedForNonAdmin() {

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);

        when(mockSecurityContextAccessor.getClientId()).thenReturn("bar");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setChangeMode(ADD);
        assertThrowsWithMessageThat(InvalidClientDetailsException.class, () -> endpoints.changeSecret(detail.getClientId(), change), is("Bad request. Not permitted to change another client's secret"));
    }

    @Test
    void testChangeSecretDeniedWhenOldSecretNotProvided() {

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);


        when(authenticationManager.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));


        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        assertThrowsWithMessageThat(InvalidClientDetailsException.class, () -> endpoints.changeSecret(detail.getClientId(), change), is("Previous secret is required and must be valid"));

    }

    @Test
    void testChangeSecretByAdmin() {

        when(clientDetailsService.retrieve(detail.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(detail);

        when(mockSecurityContextAccessor.getClientId()).thenReturn("admin");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(detail.getClientSecret());
        change.setSecret("newpassword");
        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).updateClientSecret(detail.getClientId(), "newpassword", "testzone");

    }


    @Test
    void testChangeSecretDeniedTooLong() {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 0, 6));
        String complexPolicySatisfyingSecret = "Secret1@";

        when(clientDetailsService.retrieve(detail.getClientId(), testZone.getId())).thenReturn(detail);

        when(mockSecurityContextAccessor.getClientId()).thenReturn("admin");
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(detail.getClientSecret());
        change.setSecret(complexPolicySatisfyingSecret);
        assertThrows(InvalidClientSecretException.class, () -> endpoints.changeSecret(detail.getClientId(), change));
    }

    @Test
    void testRemoveClientDetailsAdminCaller() throws Exception {
        Mockito.when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);
        Mockito.when(clientDetailsService.retrieve("foo", IdentityZoneHolder.get().getId())).thenReturn(detail);
        ClientDetails result = endpoints.removeClientDetails("foo");
        assertNull(result.getClientSecret());
        ArgumentCaptor<EntityDeletedEvent> captor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(endpoints).publish(captor.capture());
        verify(clientRegistrationService).removeClientDetails("foo");
        assertNotNull(captor.getValue());
        Object deleted = captor.getValue().getDeleted();
        assertNotNull(deleted);
        assertTrue(deleted instanceof ClientDetails);
        assertEquals("foo", ((ClientDetails) deleted).getClientId());
    }

    @Test
    void testScopeIsRestrictedByCaller() {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
                "uaa.none");
        when(clientDetailsService.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        detail.setScope(Collections.singletonList("some"));
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(detail));
    }

    @Test
    void testValidScopeIsNotRestrictedByCaller() throws Exception {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
                "uaa.none");
        when(clientDetailsService.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        detail.setScope(Collections.singletonList("none"));
        endpoints.createClientDetails(detail);
    }

    @Test
    void testClientEndpointCannotBeConfiguredWithAnInvalidMaxCount() {
        assertThrowsWithMessageThat(IllegalArgumentException.class, () -> endpoints.setClientMaxCount(0),
                is("Invalid \"clientMaxCount\" value (got 0). Should be positive number.")
        );
    }

    @Test
    void testAuthorityIsRestrictedByCaller() {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
                "uaa.none");
        when(clientDetailsService.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        detail.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.some"));
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(detail));
    }

    @Test
    void testAuthorityAllowedByCaller() throws Exception {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "uaa.none", "client_credentials,implicit",
                "uaa.none");
        when(clientDetailsService.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        when(mockSecurityContextAccessor.getClientId()).thenReturn("caller");
        detail.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        endpoints.createClientDetails(detail);
    }

    @Test
    void cannotExpandScope() {
        BaseClientDetails caller = new BaseClientDetails();
        caller.setScope(Collections.singletonList("none"));
        when(clientDetailsService.retrieve("caller", IdentityZoneHolder.get().getId())).thenReturn(caller);
        detail.setAuthorizedGrantTypes(Collections.singletonList("implicit"));
        detail.setClientSecret("hello");
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(detail));
    }

    @Test
    void implicitClientWithNonEmptySecretIsRejected() {
        detail.setAuthorizedGrantTypes(Collections.singletonList("implicit"));
        detail.setClientSecret("hello");
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(detail));
    }

    @Test
    void implicitAndAuthorizationCodeClientIsRejected() {
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit", GRANT_TYPE_AUTHORIZATION_CODE));
        detail.setClientSecret("hello");
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(detail));
    }

    @Test
    void implicitAndAuthorizationCodeClientIsRejectedWithNullPassword() {
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit", GRANT_TYPE_AUTHORIZATION_CODE));
        detail.setClientSecret(null);
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(detail));
    }

    @Test
    void implicitAndAuthorizationCodeClientIsRejectedForAdmin() {
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit", GRANT_TYPE_AUTHORIZATION_CODE));
        detail.setClientSecret("hello");
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(detail));
    }

    @Test
    void nonImplicitClientWithEmptySecretIsRejected() {
        detail.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        detail.setClientSecret("");
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(detail));
    }

    @Test
    void updateNonImplicitClientWithEmptySecretIsOk() throws Exception {
        Mockito.when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);
        detail.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        detail.setClientSecret(null);
        endpoints.updateClientDetails(detail, detail.getClientId());
    }

    @Test
    void updateNonImplicitClientAndMakeItImplicit() {
        assertFalse(detail.getAuthorizedGrantTypes().contains("implicit"));
        detail.setAuthorizedGrantTypes(Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, "implicit"));
        detail.setClientSecret(null);
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.updateClientDetails(detail, detail.getClientId()));
    }

    @Test
    void invalidGrantTypeIsRejected() {
        detail.setAuthorizedGrantTypes(Collections.singletonList("not_a_grant_type"));
        assertThrows(InvalidClientDetailsException.class, () -> endpoints.createClientDetails(detail));
    }

    @Test
    void testHandleNoSuchClient() {
        ResponseEntity<Void> result = endpoints.handleNoSuchClient(new NoSuchClientException("No such client: foo"));
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }

    @Test
    void testHandleClientAlreadyExists() {
        ResponseEntity<InvalidClientDetailsException> result = endpoints
                .handleClientAlreadyExists(new ClientAlreadyExistsException("No such client: foo"));
        assertEquals(HttpStatus.CONFLICT, result.getStatusCode());
    }

    @Test
    void testErrorHandler() {
        ResponseEntity<InvalidClientDetailsException> result = endpoints
                .handleInvalidClientDetails(new InvalidClientDetailsException("No such client: foo"));
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals(1, endpoints.getErrorCounts().size());
    }

    @Test
    void testCreateClientWithAutoapproveScopesList() throws Exception {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("foo.read");
        input.setScope(scopes);
        detail.setScope(scopes);
        input.setAutoApproveScopes(autoApproveScopes);
        detail.setAutoApproveScopes(autoApproveScopes);
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        verify(clientDetailsService).create(clientCaptor.capture(), anyString());
        BaseClientDetails created = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, created.getAutoApproveScopes());
        assertTrue(created.isAutoApprove("foo.read"));
        assertFalse(created.isAutoApprove("foo.write"));
    }

    private static void assertSetEquals(Collection<?> a, Collection<?> b) {
        assertTrue("expected " + a + " but was " + b, a == null && b == null || a != null && b != null && a.containsAll(b) && b.containsAll(a));
    }

    @Test
    void testCreateClientWithAutoapproveScopesTrue() throws Exception {
        when(clientDetailsService.retrieve(anyString(), anyString())).thenReturn(input);
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("true");
        input.setScope(scopes);
        detail.setScope(scopes);
        input.setAutoApproveScopes(autoApproveScopes);
        detail.setAutoApproveScopes(autoApproveScopes);
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        verify(clientDetailsService).create(clientCaptor.capture(), anyString());
        BaseClientDetails created = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, created.getAutoApproveScopes());
        assertTrue(created.isAutoApprove("foo.read"));
        assertTrue(created.isAutoApprove("foo.write"));
    }

    @Test
    void testUpdateClientWithAutoapproveScopesList() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(input));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("foo.read");

        input.setScope(scopes);
        detail.setScope(scopes);
        detail.setAutoApproveScopes(autoApproveScopes);

        ClientDetails result = endpoints.updateClientDetails(detail, input.getClientId());
        assertNull(result.getClientSecret());
        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        verify(clientRegistrationService).updateClientDetails(clientCaptor.capture(), anyString());
        BaseClientDetails updated = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, updated.getAutoApproveScopes());
        assertTrue(updated.isAutoApprove("foo.read"));
        assertFalse(updated.isAutoApprove("foo.write"));
    }

    @Test
    void testUpdateClientWithAutoapproveScopesTrue() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId(), IdentityZoneHolder.get().getId())).thenReturn(
                new BaseClientDetails(input));
        when(mockSecurityContextAccessor.getClientId()).thenReturn(detail.getClientId());
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);

        List<String> scopes = Arrays.asList("foo.read", "foo.write");
        List<String> autoApproveScopes = Collections.singletonList("true");

        input.setScope(scopes);
        detail.setScope(scopes);
        detail.setAutoApproveScopes(autoApproveScopes);

        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        ClientDetails result = endpoints.updateClientDetails(detail, input.getClientId());
        assertNull(result.getClientSecret());
        verify(clientRegistrationService).updateClientDetails(clientCaptor.capture(), anyString());
        BaseClientDetails updated = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, updated.getAutoApproveScopes());
        assertTrue(updated.isAutoApprove("foo.read"));
        assertTrue(updated.isAutoApprove("foo.write"));
    }
}
