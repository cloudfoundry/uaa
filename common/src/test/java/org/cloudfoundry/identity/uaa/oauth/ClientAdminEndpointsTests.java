/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.oauth.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.oauth.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.rest.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.rest.ResourceMonitor;
import org.cloudfoundry.identity.uaa.rest.SearchResults;
import org.cloudfoundry.identity.uaa.rest.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.StubSecurityContextAccessor;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.NoSuchClientException;

/**
 * @author Dave Syer
 *
 */
public class ClientAdminEndpointsTests {

    private ClientAdminEndpoints endpoints = null;

    private BaseClientDetails input = null;

    private ClientDetailsModification[] inputs = new ClientDetailsModification[5];

    private BaseClientDetails detail = null;

    private BaseClientDetails[] details = new BaseClientDetails[inputs.length];


    private QueryableResourceManager<ClientDetails> clientDetailsService = null;

    private SecurityContextAccessor securityContextAccessor = null;

    private ClientRegistrationService clientRegistrationService = null;

    private AuthenticationManager authenticationManager = null;

    private ApprovalStore approvalStore = null;

    private ClientAdminEndpointsValidator clientDetailsValidator = null;

    @Rule
    public ExpectedException expected = ExpectedException.none();

    private ResourceMonitor<ClientDetails> clientDetailsResourceMonitor;

    @Before
    public void setUp() throws Exception {
        endpoints = new ClientAdminEndpoints();

        clientDetailsService = Mockito.mock(QueryableResourceManager.class);
        clientDetailsResourceMonitor = Mockito.mock(ResourceMonitor.class);
        securityContextAccessor = Mockito.mock(SecurityContextAccessor.class);
        clientRegistrationService = Mockito.mock(ClientRegistrationService.class);
        authenticationManager = Mockito.mock(AuthenticationManager.class);
        approvalStore = mock(ApprovalStore.class);
        clientDetailsValidator = new ClientAdminEndpointsValidator();
        clientDetailsValidator.setClientDetailsService(clientDetailsService);
        clientDetailsValidator.setSecurityContextAccessor(securityContextAccessor);

        endpoints.setClientDetailsService(clientDetailsService);
        endpoints.setClientRegistrationService(clientRegistrationService);
        endpoints.setSecurityContextAccessor(securityContextAccessor);
        endpoints.setAuthenticationManager(authenticationManager);
        endpoints.setApprovalStore(approvalStore);
        endpoints.setClientDetailsValidator(clientDetailsValidator);
        endpoints.setClientDetailsResourceMonitor(clientDetailsResourceMonitor);

        Map<String, String> attributeNameMap = new HashMap<String, String>();
        attributeNameMap.put("client_id", "clientId");
        attributeNameMap.put("resource_ids", "resourceIds");
        attributeNameMap.put("authorized_grant_types", "authorizedGrantTypes");
        attributeNameMap.put("redirect_uri", "registeredRedirectUri");
        attributeNameMap.put("access_token_validity", "accessTokenValiditySeconds");
        attributeNameMap.put("refresh_token_validity", "refreshTokenValiditySeconds");
        endpoints.setAttributeNameMapper(new SimpleAttributeNameMapper(attributeNameMap));

        input = new BaseClientDetails();
        input.setClientId("foo");
        input.setClientSecret("secret");
        input.setAuthorizedGrantTypes(Arrays.asList("authorization_code"));

        for (int i=0; i<inputs.length; i++) {
            inputs[i] = new ClientDetailsModification();
            inputs[i].setClientId("foo-"+i);
            inputs[i].setClientSecret("secret-"+i);
            inputs[i].setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
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


        endpoints.afterPropertiesSet();
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
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        Mockito.verify(clientRegistrationService).addClientDetails(detail);
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
        ClientDetailsModification nonexist = new ClientDetailsModification("unknown","","","","");
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
        input.setAuthorizedGrantTypes(Arrays.asList("client_credentials"));
        detail.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        Mockito.verify(clientRegistrationService).addClientDetails(detail);
    }

    @Test
    public void testCreateClientDetailsWithAdditionalInformation() throws Exception {
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        detail.setAdditionalInformation(input.getAdditionalInformation());
        ClientDetails result = endpoints.createClientDetails(input);
        assertNull(result.getClientSecret());
        Mockito.verify(clientRegistrationService).addClientDetails(detail);
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
        Mockito.verify(clientRegistrationService).addClientDetails(detail);
    }

    @Test
    public void testFindClientDetails() throws Exception {
        Mockito.when(clientDetailsService.query("filter", "sortBy", true)).thenReturn(
            Arrays.<ClientDetails> asList(detail));
        SearchResults<?> result = endpoints.listClientDetails("client_id", "filter", "sortBy", "ascending", 1, 100);
        assertEquals(1, result.getResources().size());
        Mockito.verify(clientDetailsService).query("filter", "sortBy", true);

        result = endpoints.listClientDetails("", "filter", "sortBy", "ascending", 1, 100);
        assertEquals(1, result.getResources().size());
    }

    @Test(expected = UaaException.class)
    public void testFindClientDetailsInvalidFilter() throws Exception {
        Mockito.when(clientDetailsService.query("filter", "sortBy", true)).thenThrow(new IllegalArgumentException());
        endpoints.listClientDetails("client_id", "filter", "sortBy", "ascending", 1, 100);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testUpdateClientDetailsWithNullCallerAndInvalidScope() throws Exception {
        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenReturn(
            new BaseClientDetails(input));
        input.setScope(Arrays.asList("read"));
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        detail.setScope(Arrays.asList("read"));
        Mockito.verify(clientRegistrationService).updateClientDetails(detail);
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
        Mockito.verify(clientRegistrationService).updateClientDetails(detail);
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
        Mockito.verify(clientRegistrationService).updateClientDetails(detail);
    }

    @Test
    public void testUpdateClientDetailsRemoveAdditionalInformation() throws Exception {
        input.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        Mockito.when(clientDetailsService.retrieve(input.getClientId())).thenReturn(
            new BaseClientDetails(input));
        input.setAdditionalInformation(Collections.<String, Object> emptyMap());
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        Mockito.verify(clientRegistrationService).updateClientDetails(detail);
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
        ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
        assertNull(result.getClientSecret());
        Mockito.verify(clientRegistrationService).updateClientDetails(updated);
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
        Mockito.verify(clientRegistrationService).updateClientSecret(detail.getClientId(), "newpassword");

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
    public void testChangeSecretDeniedWhenOldSecretNotProvidedEvenFormAdmin() throws Exception {

        when(clientDetailsService.retrieve(detail.getClientId())).thenReturn(detail);
        when(authenticationManager.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));
        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getClientId()).thenReturn(detail.getClientId());
        when(sca.isClient()).thenReturn(true);
        when(sca.isAdmin()).thenReturn(true);
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
        Mockito.verify(clientRegistrationService).updateClientSecret(detail.getClientId(), "newpassword");

    }

    @Test
    public void testRemoveClientDetailsAdminCaller() throws Exception {
        Mockito.when(securityContextAccessor.isAdmin()).thenReturn(true);
        Mockito.when(clientDetailsService.retrieve("foo")).thenReturn(detail);
        ClientDetails result = endpoints.removeClientDetails("foo");
        assertNull(result.getClientSecret());
        Mockito.verify(clientRegistrationService).removeClientDetails("foo");
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
        Mockito.verify(clientRegistrationService).addClientDetails(clientCaptor.capture());
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
        Mockito.verify(clientRegistrationService).addClientDetails(clientCaptor.capture());
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
        Mockito.verify(clientRegistrationService).updateClientDetails(clientCaptor.capture());
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

        Mockito.verify(clientRegistrationService).updateClientDetails(clientCaptor.capture());
        BaseClientDetails updated = clientCaptor.getValue();
        assertSetEquals(autoApproveScopes, updated.getAutoApproveScopes());
        assertTrue(updated.isAutoApprove("foo.read"));
        assertTrue(updated.isAutoApprove("foo.write"));
    }

}