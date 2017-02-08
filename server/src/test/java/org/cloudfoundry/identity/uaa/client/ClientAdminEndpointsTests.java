/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

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
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.StubSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

public class ClientAdminEndpointsTests {

    private ClientAdminEndpoints endpoints = null;

    private BaseClientDetails input = null;

    private ClientDetailsModification[] inputs = new ClientDetailsModification[5];

    private BaseClientDetails detail = null;

    private BaseClientDetails[] details = new BaseClientDetails[inputs.length];


    private QueryableResourceManager<ClientDetails> clientDetailsService = null;

    private ClientMetadataProvisioning clientMetadataProvisioning = null;

    private SecurityContextAccessor securityContextAccessor = null;

    private ClientServicesExtension clientRegistrationService = null;

    private AuthenticationManager authenticationManager = null;

    private ApprovalStore approvalStore = null;

    private ClientAdminEndpointsValidator clientDetailsValidator = null;

    private static final Set<String> SINGLE_REDIRECT_URL = Collections.singleton("http://redirect.url");

    private IdentityZone testZone = new IdentityZone();

    @Rule
    public ExpectedException expected = ExpectedException.none();

    private ResourceMonitor<ClientDetails> clientDetailsResourceMonitor;

    private static abstract class NoOpClientDetailsResourceManager implements QueryableResourceManager<ClientDetails> {
        @Override
        public ClientDetails create(ClientDetails resource) {
            Map<String, Object> additionalInformation = new HashMap<>(resource.getAdditionalInformation());
            additionalInformation.put("lastModified", 1463510591);

            BaseClientDetails altered = new BaseClientDetails(resource);
            altered.setAdditionalInformation(additionalInformation);

            return altered;
        }
    }

    @Before
    public void setUp() throws Exception {
        endpoints = spy(new ClientAdminEndpoints());

        clientDetailsService = Mockito.mock(NoOpClientDetailsResourceManager.class);
        when(clientDetailsService.create(any(ClientDetails.class))).thenCallRealMethod();
        clientDetailsResourceMonitor = Mockito.mock(ResourceMonitor.class);
        securityContextAccessor = Mockito.mock(SecurityContextAccessor.class);
        clientRegistrationService = Mockito.mock(ClientServicesExtension.class, withSettings().extraInterfaces(SystemDeletable.class));
        authenticationManager = Mockito.mock(AuthenticationManager.class);
        approvalStore = mock(ApprovalStore.class);
        clientDetailsValidator = new ClientAdminEndpointsValidator();
        clientMetadataProvisioning = mock(ClientMetadataProvisioning.class);
        clientDetailsValidator.setClientDetailsService(clientDetailsService);
        clientDetailsValidator.setSecurityContextAccessor(securityContextAccessor);
        clientDetailsValidator.setClientSecretValidator(
                new ZoneAwareClientSecretPolicyValidator(new ClientSecretPolicy(0,255,0,0,0,0,6)));

        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0,255,0,0,0,0,6));
        IdentityZoneHolder.set(testZone);

        endpoints.setClientDetailsService(clientDetailsService);
        endpoints.setClientRegistrationService(clientRegistrationService);
        endpoints.setSecurityContextAccessor(securityContextAccessor);
        endpoints.setAuthenticationManager(authenticationManager);
        endpoints.setApprovalStore(approvalStore);
        endpoints.setClientDetailsValidator(clientDetailsValidator);
        endpoints.setRestrictedScopesValidator(new RestrictUaaScopesClientValidator(new UaaScopes()));
        endpoints.setClientDetailsResourceMonitor(clientDetailsResourceMonitor);

        Map<String, String> attributeNameMap = new HashMap<String, String>();
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
        input.setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
        input.setRegisteredRedirectUri(SINGLE_REDIRECT_URL);

        for (int i=0; i<inputs.length; i++) {
            inputs[i] = new ClientDetailsModification();
            inputs[i].setClientId("foo-"+i);
            inputs[i].setClientSecret("secret-"+i);
            inputs[i].setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
            inputs[i].setRegisteredRedirectUri(new HashSet(Arrays.asList("https://foo-"+i)));
            inputs[i].setAccessTokenValiditySeconds(300);
        }

        detail = new BaseClientDetails(input);
        detail.setResourceIds(Arrays.asList("none"));
        // refresh token is added automatically by endpoint validation
        detail.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token"));
        detail.setScope(Arrays.asList("uaa.none"));
        detail.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));

        for (int i=0; i<details.length; i++) {
            details[i] = new BaseClientDetails(inputs[i]);
            details[i].setResourceIds(Arrays.asList("none"));
            // refresh token is added automatically by endpoint validation
            details[i].setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token"));
            details[i].setScope(Arrays.asList("uaa.none"));
            details[i].setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        }

        endpoints.setApplicationEventPublisher(
            new ApplicationEventPublisher() {
                @Override
                public void publishEvent(ApplicationEvent event) {
                    if (event instanceof EntityDeletedEvent) {
                        ClientDetails client = (ClientDetails)((EntityDeletedEvent)event).getDeleted();
                        clientRegistrationService.removeClientDetails(client.getClientId());
                    }
                }
                @Override
                public void publishEvent(Object event) {}
            }
        );
        endpoints.afterPropertiesSet();
    }

    @After
    public void tearDown() {
        IdentityZoneHolder.clear();
    }

    private void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
        endpoints.setSecurityContextAccessor(securityContextAccessor);
        clientDetailsValidator.setSecurityContextAccessor(securityContextAccessor);
    }

    @Test
    public void testValidateClientsTransferAutoApproveScopeSet() throws Exception {
        List<String> scopes = Arrays.asList("scope1", "scope2");
        input.setAutoApproveScopes(new HashSet<String>(scopes));
        ClientDetails test = endpoints.getClientDetailsValidator().validate(input, Mode.CREATE);
        for (String scope:scopes) {
            assertTrue("Client should have "+scope+" autoapprove.", test.isAutoApprove(scope));
        }
    }

    @Test
    public void testAccessors() throws Exception {
        ApprovalStore as = mock(ApprovalStore.class);
        endpoints.setApprovalStore(as);
        assertSame(as, endpoints.getApprovalStore());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testNoApprovalStore() {
        endpoints.setApprovalStore(null);
        endpoints.deleteApprovals("someclient");
    }

    @Test
    public void testStatistics() throws Exception {
        assertEquals(0, endpoints.getClientDeletes());
        assertEquals(0, endpoints.getClientSecretChanges());
        assertEquals(0, endpoints.getClientUpdates());
        assertEquals(0, endpoints.getErrorCounts().size());
        assertEquals(0, endpoints.getTotalClients());
    }

    @Test
    public void testCreateClientDetails() throws Exception {
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        verify(clientDetailsService).create(detail);
        assertEquals(1463510591, result.getAdditionalInformation().get("lastModified"));
    }

    @Test(expected = InvalidClientSecretException.class)
    public void testCreateClientDetails_With_Secret_Length_Less_Than_MinLength() throws Exception {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(7,255,0,0,0,0,6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(input);
    }

    @Test(expected = InvalidClientSecretException.class)
    public void testCreateClientDetails_With_Secret_Length_Greater_Than_MaxLength() throws Exception {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0,5,0,0,0,0,6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(input);
    }

    @Test(expected = InvalidClientSecretException.class)
    public void testCreateClientDetails_With_Secret_Require_Digit() throws Exception {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0,5,0,0,1,0,6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(input);
    }

    @Test(expected = InvalidClientSecretException.class)
    public void testCreateClientDetails_With_Secret_Require_Uppercase() throws Exception {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0,5,1,0,0,0,6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(input);
    }

    @Test(expected = InvalidClientSecretException.class)
    public void testCreateClientDetails_With_Secret_Require_Lowercase() throws Exception {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0,5,0,1,0,0,6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(input);
    }

    @Test(expected = InvalidClientSecretException.class)
    public void testCreateClientDetails_With_Secret_Require_Special_Character() throws Exception {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0,5,0,0,0,1,6));
        IdentityZoneHolder.set(testZone);
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(input);
    }

    @Test
    public void testCreateClientDetails_With_Secret_Satisfying_Complex_Policy() throws Exception {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(6,255,1,1,1,1,6));
        IdentityZoneHolder.set(testZone);
        String complexPolicySatisfyingSecret = "Secret1@";
        input.setClientSecret(complexPolicySatisfyingSecret);
        detail.setClientSecret(complexPolicySatisfyingSecret);
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        verify(clientDetailsService).create(detail);
        assertEquals(1463510591, result.getAdditionalInformation().get("lastModified"));
    }

    @Test
    public void test_Get_Restricted_Scopes_List() throws Exception {
        assertEquals(new UaaScopes().getUaaScopes(), endpoints.getRestrictedClientScopes());
        endpoints.setRestrictedScopesValidator(null);
        assertNull(endpoints.getRestrictedClientScopes());
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testCannot_Create_Restricted_Client_Invalid_Scopes() throws Exception {
        input.setScope(new UaaScopes().getUaaScopes());
        endpoints.createRestrictedClientDetails(input);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testCannot_Create_Restricted_Client_Invalid_Authorities() throws Exception {
        input.setAuthorities(new UaaScopes().getUaaAuthorities());
        endpoints.createRestrictedClientDetails(input);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testCannot_Update_Restricted_Client_Invalid_Scopes() throws Exception {
        input.setScope(new UaaScopes().getUaaScopes());
        endpoints.updateRestrictedClientDetails(input, input.getClientId());
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testCannot_Update_Restricted_Client_Invalid_Authorities() throws Exception {
        input.setAuthorities(new UaaScopes().getUaaAuthorities());
        endpoints.updateRestrictedClientDetails(input, input.getClientId());
    }

    @Test(expected = NoSuchClientException.class)
    public void testMultipleCreateClientDetailsNullArray() throws Exception {
        endpoints.createClientDetailsTx(null);
    }

    @Test(expected = NoSuchClientException.class)
    public void testMultipleCreateClientDetailsEmptyArray() throws Exception {
        endpoints.createClientDetailsTx(new ClientDetailsModification[0]);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testMultipleCreateClientDetailsNonExistent() throws Exception {
        ClientDetailsModification detailsModification = new ClientDetailsModification();
        detailsModification.setClientId("unknown");
        ClientDetailsModification nonexist = detailsModification;
        endpoints.createClientDetailsTx(new ClientDetailsModification[]{nonexist});
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testMultipleUpdateClientDetailsNullArray() throws Exception {
        endpoints.updateClientDetailsTx(null);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testMultipleUpdateClientDetailsEmptyArray() throws Exception {
        endpoints.updateClientDetailsTx(new ClientDetailsModification[0]);
    }


    @Test
    public void testMultipleCreateClientDetails() throws Exception {
        ClientDetails[] results = endpoints.createClientDetailsTx(inputs);
        assertEquals("We should have created "+inputs.length+" clients.", inputs.length, results.length);
        for (int i=0; i<inputs.length; i++) {
            ClientDetails result = results[i];
            assertNull(result.getClientSecret());
        }
        //TODO figure out how to verify all five invocations
        //Mockito.verify(clientRegistrationService, times(inputs.length)).addClientDetails(details[0]);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateClientDetailsWithReservedId() throws Exception {
        input.setClientId("uaa");
        ClientDetails result = endpoints.createClientDetails(input);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateMultipleClientDetailsWithReservedId() throws Exception {
        inputs[inputs.length-1].setClientId("uaa");
        ClientDetails[] result = endpoints.createClientDetailsTx(inputs);
    }


    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateClientDetailsWithNoGrantType() throws Exception {
        input.setAuthorizedGrantTypes(Collections.<String>emptySet());
        ClientDetails result = endpoints.createClientDetails(input);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateMultipleClientDetailsWithNoGrantType() throws Exception {
        inputs[inputs.length-1].setAuthorizedGrantTypes(Collections.<String>emptySet());
        ClientDetails[] result = endpoints.createClientDetailsTx(inputs);
    }


    @Test
    public void testCreateClientDetailsWithClientCredentials() throws Exception {
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        input.setAuthorizedGrantTypes(Arrays.asList("client_credentials"));
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        verify(clientDetailsService).create(detail);
    }

    @Test
    public void testCreateClientDetailsWithAdditionalInformation() throws Exception {
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        detail.setAdditionalInformation(input.getAdditionalInformation());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        verify(clientDetailsService).create(detail);
    }

    @Test
    public void testResourceServerCreation() throws Exception {
        detail.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.resource"));
        detail.setScope(Arrays.asList(detail.getClientId() + ".some"));
        detail.setAuthorizedGrantTypes(Arrays.asList("client_credentials"));
        endpoints.createClientDetails(detail);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateClientDetailsWithPasswordGrant() throws Exception {
        input.setAuthorizedGrantTypes(Arrays.asList("password"));
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        verify(clientRegistrationService).addClientDetails(detail);
    }

    @Test
    public void testFindClientDetails() throws Exception {
        Mockito.when(clientDetailsService.query("filter", "sortBy", true)).thenReturn(
            Arrays.<ClientDetails> asList(detail));
        SearchResults<?> result = endpoints.listClientDetails("client_id", "filter", "sortBy", "ascending", 1, 100);
        assertEquals(1, result.getResources().size());
        verify(clientDetailsService).query("filter", "sortBy", true);

        result = endpoints.listClientDetails("", "filter", "sortBy", "ascending", 1, 100);
        assertEquals(1, result.getResources().size());
    }

    @Test(expected = UaaException.class)
    public void testFindClientDetailsInvalidFilter() throws Exception {
        Mockito.when(clientDetailsService.query("filter", "sortBy", true)).thenThrow(new IllegalArgumentException());
        endpoints.listClientDetails("client_id", "filter", "sortBy", "ascending", 1, 100);
    }

    @Test
    public void testFindClientDetails_Test_Attribute_Filter() throws Exception {
        when(clientDetailsService.query(anyString(), anyString(), anyBoolean())).thenReturn(Arrays.asList(inputs));
        for (String attribute : Arrays.asList("client_id", "resource_ids", "authorized_grant_types", "redirect_uri", "access_token_validity", "refresh_token_validity", "autoapprove","additionalinformation")) {
            SearchResults<Map<String, Object>> result = (SearchResults<Map<String, Object>>) endpoints.listClientDetails(attribute, "client_id pr", "sortBy", "ascending", 1, 100);
            validateAttributeResults(result, 5, Arrays.asList(attribute));
        }


    }

    protected void validateAttributeResults(SearchResults<Map<String,Object>> result , int size, List<String> attributes) {
        assertEquals(5, result.getResources().size());
        for (String s : attributes) {
            result.getResources().stream().forEach((map) ->
                assertTrue("Expecting attribute "+s+" to be present", map.containsKey(s))
            );
        }
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testUpdateClientDetailsWithNullCallerAndInvalidScope() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenReturn(
            new BaseClientDetails(input));
        input.setScope(Arrays.asList("read"));
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        detail.setScope(Arrays.asList("read"));
        verify(clientRegistrationService).updateClientDetails(detail);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testNonExistentClient1() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenThrow(new InvalidClientDetailsException(""));
        endpoints.getClientDetails(input.getClientId());
    }

    @Test(expected = NoSuchClientException.class)
    public void testNonExistentClient2() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenThrow(new BadClientCredentialsException());
        endpoints.getClientDetails(input.getClientId());
    }

    @Test
    public void testGetClientDetails() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenReturn(input);
        input.setScope(Arrays.asList(input.getClientId() + ".read"));
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        ClientDetails result = endpoints.getClientDetails(input.getClientId());
        assertNull(result.getClientSecret());
        assertEquals(input.getAdditionalInformation(), result.getAdditionalInformation());
    }

    @Test
    public void testUpdateClientDetails() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenReturn(
            new BaseClientDetails(input));
        input.setScope(Arrays.asList(input.getClientId() + ".read"));
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        detail.setScope(Arrays.asList(input.getClientId() + ".read"));
        verify(clientRegistrationService).updateClientDetails(detail);
    }

    @Test
    public void testUpdateClientDetailsWithAdditionalInformation() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenReturn(
            new BaseClientDetails(input));
        input.setScope(Arrays.asList(input.getClientId() + ".read"));
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        detail.setScope(input.getScope());
        detail.setAdditionalInformation(input.getAdditionalInformation());
        verify(clientRegistrationService).updateClientDetails(detail);
    }

    @Test
    public void testUpdateClientDetailsRemoveAdditionalInformation() throws Exception {
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenReturn(
            new BaseClientDetails(input));
        input.setAdditionalInformation(Collections.<String, Object> emptyMap());
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        verify(clientRegistrationService).updateClientDetails(detail);
    }

    @Test
    public void testPartialUpdateClientDetails() throws Exception {
        BaseClientDetails updated = new BaseClientDetails(detail);
        input = new BaseClientDetails();
        input.setClientId("foo");
        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenReturn(detail);
        input.setScope(Arrays.asList("foo.write"));
        updated.setScope(input.getScope());
        updated.setClientSecret(null);
        updated.setRegisteredRedirectUri(SINGLE_REDIRECT_URL);
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        verify(clientRegistrationService).updateClientDetails(updated);
    }

    @Test
    public void testChangeSecret() throws Exception {
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(auth);

        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);
        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn(detail.getClientId());
        when(sca.isClient()).thenReturn(true);
        setSecurityContextAccessor(sca);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(detail.getClientSecret());
        change.setSecret("newpassword");
        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).updateClientSecret(detail.getClientId(), "newpassword");

    }

    @Test
    public void testAddSecret() {
        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn("bar");
        when(sca.isClient()).thenReturn(true);
        when(sca.isAdmin()).thenReturn(true);
        setSecurityContextAccessor(sca);

        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setChangeMode(ADD);

        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).addClientSecret(detail.getClientId(), "newpassword");
    }

    @Test
    public void testAddingThirdSecretForClient() {
        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn("bar");
        when(sca.isClient()).thenReturn(true);
        when(sca.isAdmin()).thenReturn(true);
        setSecurityContextAccessor(sca);

        detail.setClientSecret("hash1 hash2");
        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setOldSecret("hash1");
        change.setChangeMode(ADD);
        expected.expect(InvalidClientDetailsException.class);
        expected.expectMessage("client secret is either empty or client already has two secrets.");
        endpoints.changeSecret(detail.getClientId(), change);
    }

    @Test
    public void testDeleteSecret() {
        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn("bar");
        when(sca.isClient()).thenReturn(true);
        when(sca.isAdmin()).thenReturn(true);
        setSecurityContextAccessor(sca);

        detail.setClientSecret("hash1 hash2");
        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);
        SecretChangeRequest change = new SecretChangeRequest();
        change.setChangeMode(DELETE);

        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).deleteClientSecret(detail.getClientId());
    }

    @Test
    public void testDeleteSecretWhenOnlyOneSecret() {
        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn("bar");
        when(sca.isClient()).thenReturn(true);
        when(sca.isAdmin()).thenReturn(true);
        setSecurityContextAccessor(sca);

        detail.setClientSecret("hash1");
        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);
        SecretChangeRequest change = new SecretChangeRequest();
        change.setChangeMode(DELETE);

        expected.expect(InvalidClientDetailsException.class);
        expected.expectMessage("client secret is either empty or client has only one secret.");

        endpoints.changeSecret(detail.getClientId(), change);
    }

    @Test
    public void testChangeSecretDeniedForUser() throws Exception {

        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);

        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn(detail.getClientId());
        when(sca.isClient()).thenReturn(false);
        setSecurityContextAccessor(sca);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(detail.getClientSecret());
        change.setSecret("newpassword");
        expected.expect(InvalidClientDetailsException.class);
        expected.expectMessage("Only a client");
        endpoints.changeSecret(detail.getClientId(), change);

    }

    @Test
    public void testChangeSecretDeniedForNonAdmin() throws Exception {

        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);

        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn("bar");
        when(sca.isClient()).thenReturn(true);
        when(sca.isAdmin()).thenReturn(false);
        setSecurityContextAccessor(sca);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        expected.expect(InvalidClientDetailsException.class);
        expected.expectMessage("Not permitted to change");
        endpoints.changeSecret(detail.getClientId(), change);

    }

    @Test
    public void testAddSecretDeniedForNonAdmin() throws Exception {

        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);

        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn("bar");
        when(sca.isClient()).thenReturn(true);
        when(sca.isAdmin()).thenReturn(false);
        setSecurityContextAccessor(sca);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        change.setChangeMode(ADD);
        expected.expect(InvalidClientDetailsException.class);
        expected.expectMessage("Not permitted to change");
        endpoints.changeSecret(detail.getClientId(), change);

    }

    @Test
    public void testChangeSecretDeniedWhenOldSecretNotProvided() throws Exception {

        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);


        when(authenticationManager.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));


        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn(detail.getClientId());
        when(sca.isClient()).thenReturn(true);
        when(sca.isAdmin()).thenReturn(false);
        setSecurityContextAccessor(sca);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setSecret("newpassword");
        expected.expect(InvalidClientDetailsException.class);
        expected.expectMessage("Previous secret is required");
        endpoints.changeSecret(detail.getClientId(), change);

    }

    @Test
    public void testChangeSecretByAdmin() throws Exception {

        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);

        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn("admin");
        when(sca.isClient()).thenReturn(true);
        when(sca.isAdmin()).thenReturn(true);
        setSecurityContextAccessor(sca);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(detail.getClientSecret());
        change.setSecret("newpassword");
        endpoints.changeSecret(detail.getClientId(), change);
        verify(clientRegistrationService).updateClientSecret(detail.getClientId(), "newpassword");

    }


    @Test(expected = InvalidClientSecretException.class)
    public void testChangeSecretDeniedTooLong() throws Exception {
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0,5,0,0,0,0,6));
        String complexPolicySatisfyingSecret = "Secret1@";

        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);

        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn("admin");
        when(sca.isClient()).thenReturn(true);
        when(sca.isAdmin()).thenReturn(true);
        setSecurityContextAccessor(sca);

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(detail.getClientSecret());
        change.setSecret(complexPolicySatisfyingSecret);
        endpoints.changeSecret(detail.getClientId(), change);
    }


    @Test
    public void testRemoveClientDetailsAdminCaller() throws Exception {
        Mockito.when(securityContextAccessor.isAdmin()).thenReturn(true);
        Mockito.when(clientDetailsService.retrieve("foo")).thenReturn(detail);
        ClientDetails result = endpoints.removeClientDetails("foo");
        assertNull(result.getClientSecret());
        ArgumentCaptor<EntityDeletedEvent> captor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(endpoints).publish(captor.capture());
        verify(clientRegistrationService).removeClientDetails("foo");
        assertNotNull(captor.getValue());
        Object deleted = captor.getValue().getDeleted();
        assertNotNull(deleted);
        assertTrue(deleted instanceof ClientDetails);
        assertEquals("foo", ((ClientDetails)deleted).getClientId());
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testScopeIsRestrictedByCaller() throws Exception {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
            "uaa.none");
        when(clientDetailsService.retrieve("caller")).thenReturn(caller);
        setSecurityContextAccessor(new StubSecurityContextAccessor() {
            @Override
            public String getClientId() {
                return "caller";
            }
        });
        detail.setScope(Arrays.asList("some"));
        endpoints.createClientDetails(detail);
    }

    @Test
    public void testValidScopeIsNotRestrictedByCaller() throws Exception {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
            "uaa.none");
        when(clientDetailsService.retrieve("caller")).thenReturn(caller);
        setSecurityContextAccessor(new StubSecurityContextAccessor() {
            @Override
            public String getClientId() {
                return "caller";
            }
        });
        detail.setScope(Arrays.asList("none"));
        endpoints.createClientDetails(detail);
    }

    @Test
    public void testClientPrefixScopeIsNotRestrictedByClient() throws Exception {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
            "uaa.none");
        when(clientDetailsService.retrieve("caller")).thenReturn(caller);
        setSecurityContextAccessor(new StubSecurityContextAccessor() {
            @Override
            public String getClientId() {
                return "caller";
            }
        });
        detail.setScope(Arrays.asList(detail.getClientId() + ".read"));
        endpoints.createClientDetails(detail);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testAuthorityIsRestrictedByCaller() throws Exception {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
            "uaa.none");
        when(clientDetailsService.retrieve("caller")).thenReturn(caller);
        setSecurityContextAccessor(new StubSecurityContextAccessor() {
            @Override
            public String getClientId() {
                return "caller";
            }
        });
        detail.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.some"));
        endpoints.createClientDetails(detail);
    }

    @Test
    public void testAuthorityAllowedByCaller() throws Exception {
        BaseClientDetails caller = new BaseClientDetails("caller", null, "uaa.none", "client_credentials,implicit",
            "uaa.none");
        when(clientDetailsService.retrieve("caller")).thenReturn(caller);
        setSecurityContextAccessor(new StubSecurityContextAccessor() {
            @Override
            public String getClientId() {
                return "caller";
            }
        });
        detail.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        endpoints.createClientDetails(detail);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void cannotExpandScope() throws Exception {
        BaseClientDetails caller = new BaseClientDetails();
        caller.setScope(Arrays.asList("none"));
        when(clientDetailsService.retrieve("caller")).thenReturn(caller);
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit"));
        detail.setClientSecret("hello");
        endpoints.createClientDetails(detail);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void implicitClientWithNonEmptySecretIsRejected() throws Exception {
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit"));
        detail.setClientSecret("hello");
        endpoints.createClientDetails(detail);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void implicitAndAuthorizationCodeClientIsRejected() throws Exception {
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit", "authorization_code"));
        detail.setClientSecret("hello");
        endpoints.createClientDetails(detail);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void implicitAndAuthorizationCodeClientIsRejectedWithNullPassword() throws Exception {
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit", "authorization_code"));
        detail.setClientSecret(null);
        endpoints.createClientDetails(detail);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void implicitAndAuthorizationCodeClientIsRejectedForAdmin() throws Exception {
        setSecurityContextAccessor(new StubSecurityContextAccessor() {
            @Override
            public boolean isAdmin() {
                return true;
            }
        });
        detail.setAuthorizedGrantTypes(Arrays.asList("implicit", "authorization_code"));
        detail.setClientSecret("hello");
        endpoints.createClientDetails(detail);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void nonImplicitClientWithEmptySecretIsRejected() throws Exception {
        detail.setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
        detail.setClientSecret("");
        endpoints.createClientDetails(detail);
    }

    @Test
    public void updateNonImplicitClientWithEmptySecretIsOk() throws Exception {
        Mockito.when(securityContextAccessor.isAdmin()).thenReturn(true);
        detail.setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
        detail.setClientSecret(null);
        endpoints.updateClientDetails(detail, detail.getClientId());
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void updateNonImplicitClientAndMakeItImplicit() throws Exception {
        assertFalse(detail.getAuthorizedGrantTypes().contains("implicit"));
        detail.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "implicit"));
        detail.setClientSecret(null);
        endpoints.updateClientDetails(detail, detail.getClientId());
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void invalidGrantTypeIsRejected() throws Exception {
        detail.setAuthorizedGrantTypes(Arrays.asList("not_a_grant_type"));
        endpoints.createClientDetails(detail);
    }

    @Test
    public void testHandleNoSuchClient() throws Exception {
        ResponseEntity<Void> result = endpoints.handleNoSuchClient(new NoSuchClientException("No such client: foo"));
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }

    @Test
    public void testHandleClientAlreadyExists() throws Exception {
        ResponseEntity<InvalidClientDetailsException> result = endpoints
            .handleClientAlreadyExists(new ClientAlreadyExistsException("No such client: foo"));
        assertEquals(HttpStatus.CONFLICT, result.getStatusCode());
    }

    @Test
    public void testErrorHandler() throws Exception {
        ResponseEntity<InvalidClientDetailsException> result = endpoints
            .handleInvalidClientDetails(new InvalidClientDetailsException("No such client: foo"));
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals(1, endpoints.getErrorCounts().size());
    }

    @Test
    public void testCreateClientWithAutoapproveScopesList() throws Exception {
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        List<String> scopes = Arrays.asList("foo.read","foo.write");
        List<String> autoApproveScopes = Arrays.asList("foo.read");
        input.setScope(scopes);
        detail.setScope(scopes);
        input.setAutoApproveScopes(autoApproveScopes);
        detail.setAutoApproveScopes(autoApproveScopes);
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        verify(clientDetailsService).create(clientCaptor.capture());
        BaseClientDetails created = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, created.getAutoApproveScopes());
        assertTrue(created.isAutoApprove("foo.read"));
        assertFalse(created.isAutoApprove("foo.write"));
    }

    private static void assertSetEquals(Collection<?> a, Collection<?> b) {
        assertTrue("expected " + a + " but was " + b, a == null && b == null || a != null && b != null && a.containsAll(b) && b.containsAll(a));
    }

    @Test
    public void testCreateClientWithAutoapproveScopesTrue() throws Exception {
        when(clientDetailsService.retrieve(anyString())).thenReturn(input);
        List<String> scopes = Arrays.asList("foo.read","foo.write");
        List<String> autoApproveScopes = Arrays.asList("true");
        input.setScope(scopes);
        detail.setScope(scopes);
        input.setAutoApproveScopes(autoApproveScopes);
        detail.setAutoApproveScopes(autoApproveScopes);
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        verify(clientDetailsService).create(clientCaptor.capture());
        BaseClientDetails created = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, created.getAutoApproveScopes());
        assertTrue(created.isAutoApprove("foo.read"));
        assertTrue(created.isAutoApprove("foo.write"));
    }


    @Test
    public void testUpdateClientWithAutoapproveScopesList() throws Exception {
        List<String> scopes = Arrays.asList("foo.read","foo.write");
        List<String> autoApproveScopes = Arrays.asList("foo.read");

        input.setScope(scopes);
        detail.setScope(scopes);
        detail.setAutoApproveScopes(autoApproveScopes);

        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenReturn(
            new BaseClientDetails(input));
        ClientDetails result = endpoints.updateClientDetails(detail, input.getClientId());
        assertNull(result.getClientSecret());
        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        verify(clientRegistrationService).updateClientDetails(clientCaptor.capture());
        BaseClientDetails updated = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, updated.getAutoApproveScopes());
        assertTrue(updated.isAutoApprove("foo.read"));
        assertFalse(updated.isAutoApprove("foo.write"));
    }

    @Test
    public void testUpdateClientWithAutoapproveScopesTrue() throws Exception {
        List<String> scopes = Arrays.asList("foo.read","foo.write");
        List<String> autoApproveScopes = Arrays.asList("true");

        input.setScope(scopes);
        detail.setScope(scopes);
        detail.setAutoApproveScopes(autoApproveScopes);

        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenReturn(
            new BaseClientDetails(input));
        ArgumentCaptor<BaseClientDetails> clientCaptor = ArgumentCaptor.forClass(BaseClientDetails.class);
        ClientDetails result = endpoints.updateClientDetails(detail, input.getClientId());
        assertNull(result.getClientSecret());
        verify(clientRegistrationService).updateClientDetails(clientCaptor.capture());
        BaseClientDetails updated = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, updated.getAutoApproveScopes());
        assertTrue(updated.isAutoApprove("foo.read"));
        assertTrue(updated.isAutoApprove("foo.write"));
    }
}
