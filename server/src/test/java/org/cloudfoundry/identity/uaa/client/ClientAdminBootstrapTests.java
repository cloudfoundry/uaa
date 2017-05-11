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

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.StringUtils;
import org.yaml.snakeyaml.Yaml;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ClientAdminBootstrapTests extends JdbcTestBase {

    private ClientAdminBootstrap bootstrap;

    private MultitenantJdbcClientDetailsService clientRegistrationService;
    private ClientMetadataProvisioning clientMetadataProvisioning;
    @Rule
    public ExpectedException exception = ExpectedException.none();
    private ApplicationEventPublisher publisher;

    @Before
    public void setUpClientAdminTests() throws Exception {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        bootstrap = new ClientAdminBootstrap(encoder);
        clientRegistrationService = spy(new MultitenantJdbcClientDetailsService(jdbcTemplate));
        clientMetadataProvisioning = new JdbcClientMetadataProvisioning(clientRegistrationService,clientRegistrationService,jdbcTemplate);
        bootstrap.setClientRegistrationService(clientRegistrationService);
        bootstrap.setClientMetadataProvisioning(clientMetadataProvisioning);
        clientRegistrationService.setPasswordEncoder(encoder);
        publisher = mock(ApplicationEventPublisher.class);
        bootstrap.setApplicationEventPublisher(publisher);
    }

    @Test
    public void testSimpleAddClient() throws Exception {
        testSimpleAddClient("foo");
    }

    public ClientDetails testSimpleAddClient(String clientId) throws Exception {
        Map<String, Object> map = createClientMap(clientId);
        ClientDetails created = doSimpleTest(map);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        return created;
    }

    public Map<String, Object> createClientMap(String clientId) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", clientId);
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", "authorization_code");
        map.put("authorities", "uaa.none");
        map.put("redirect-uri", "http://localhost/callback");
        return map;
    }

    @Test
    public void client_slated_for_deletion_does_not_get_inserted() throws Exception {
        String autoApproveId = "autoapprove-"+new RandomValueStringGenerator().generate().toLowerCase();
        testSimpleAddClient(autoApproveId);
        reset(clientRegistrationService);
        bootstrap = spy(bootstrap);
        String clientId = "client-"+new RandomValueStringGenerator().generate().toLowerCase();
        Map<String, Map<String, Object>> clients = Collections.singletonMap(clientId, createClientMap(clientId));
        bootstrap.setClients(clients);
        bootstrap.setAutoApproveClients(singletonList(autoApproveId));
        bootstrap.setClientsToDelete(Arrays.asList(clientId, autoApproveId));
        bootstrap.afterPropertiesSet();
        verify(clientRegistrationService, never()).addClientDetails(any());
        verify(clientRegistrationService, never()).updateClientDetails(any());
        verify(clientRegistrationService, never()).updateClientSecret(any(), any());
    }

    @Test
    public void test_delete_from_yaml_existing_client() throws Exception {
        bootstrap = spy(bootstrap);
        String clientId = "client-"+new RandomValueStringGenerator().generate().toLowerCase();
        testSimpleAddClient(clientId);
        verify(bootstrap, never()).publish(any());
        bootstrap.setClientsToDelete(Arrays.asList(clientId));
        bootstrap.onApplicationEvent(new ContextRefreshedEvent(mock(ApplicationContext.class)));
        ArgumentCaptor<EntityDeletedEvent> captor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(bootstrap, times(1)).publish(captor.capture());
        assertNotNull(captor.getValue());
        verify(publisher, times(1)).publishEvent(same(captor.getValue()));
        assertEquals(clientId, captor.getValue().getObjectId());
        assertEquals(clientId, ((ClientDetails)captor.getValue().getDeleted()).getClientId());
        assertSame(SystemAuthentication.SYSTEM_AUTHENTICATION, captor.getValue().getAuthentication());
        assertNotNull(captor.getValue().getAuditEvent());
    }

    @Test
    public void test_delete_from_yaml_non_existing_client() throws Exception {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        bootstrap = spy(bootstrap);
        bootstrap.setApplicationEventPublisher(publisher);
        String clientId = "client-"+new RandomValueStringGenerator().generate().toLowerCase();
        verify(bootstrap, never()).publish(any());
        bootstrap.setClientsToDelete(Arrays.asList(clientId));
        bootstrap.onApplicationEvent(new ContextRefreshedEvent(mock(ApplicationContext.class)));
        verify(bootstrap, never()).publish(any());
        verify(publisher, never()).publishEvent(any());
    }

    public Integer countClients(String clientId) {
        return jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_client_details WHERE client_id = ? AND identity_zone_id = ?", Integer.class, clientId, IdentityZoneHolder.get().getId());
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void no_registered_redirect_url_for_auth_code() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", "authorization_code");
        map.put("authorities", "uaa.none");
        doSimpleTest(map);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void no_registered_redirect_url_for_implicit() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", "implicit");
        map.put("authorities", "uaa.none");
        doSimpleTest(map);
    }

    @Test
    public void redirect_url_not_required() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorities", "uaa.none");
        for (String grantType : Arrays.asList("password", "client_credentials", GRANT_TYPE_SAML2_BEARER, GRANT_TYPE_USER_TOKEN, GRANT_TYPE_REFRESH_TOKEN)) {
            map.put("authorized-grant-types", grantType);
            doSimpleTest(map);
        }

    }

    @Test
    public void testSimpleAddClientWithSignupSuccessRedirectUrl() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", "authorization_code");
        map.put("authorities", "uaa.none");
        map.put("signup_redirect_url", "callback_url");
        ClientDetails clientDetails = doSimpleTest(map);
        assertTrue(clientDetails.getRegisteredRedirectUri().contains("callback_url"));
    }

    @Test
    public void clientMetadata_getsBootstrapped() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("show-on-homepage", true);
        map.put("app-launch-url", "http://takemetothispage.com");
        map.put("app-icon", "bAsE64encODEd/iMAgE=");
        map.put("redirect-uri", "http://localhost/callback");
        map.put("authorized-grant-types","client_credentials");
        bootstrap.setClients(Collections.singletonMap((String) map.get("id"), map));
        bootstrap.afterPropertiesSet();

        ClientMetadata clientMetadata = clientMetadataProvisioning.retrieve("foo");
        assertTrue(clientMetadata.isShowOnHomePage());
        assertEquals("http://takemetothispage.com", clientMetadata.getAppLaunchUrl().toString());
        assertEquals("bAsE64encODEd/iMAgE=", clientMetadata.getAppIcon());
    }

    @Test
    public void testAdditionalInformation() throws Exception {
        List<String> idps = Arrays.asList("idp1", "idp1");
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", "authorization_code");
        map.put("authorities", "uaa.none");
        map.put("signup_redirect_url", "callback_url");
        map.put("change_email_redirect_url", "change_email_url");
        map.put(ClientConstants.ALLOWED_PROVIDERS, idps);
        ClientDetails created = doSimpleTest(map);
        assertEquals(idps, created.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS));
        assertTrue(created.getRegisteredRedirectUri().contains("callback_url"));
        assertTrue(created.getRegisteredRedirectUri().contains("change_email_url"));
    }

    @Test
    public void testSimpleAddClientWithChangeEmailRedirectUrl() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", "authorization_code");
        map.put("authorities", "uaa.none");
        map.put("change_email_redirect_url", "change_email_callback_url");
        ClientDetails created = doSimpleTest(map);
        assertTrue(created.getRegisteredRedirectUri().contains("change_email_callback_url"));
    }

    @Test
    public void testSimpleAddClientWithAutoApprove() throws Exception {
        ClientMetadataProvisioning clientMetadataProvisioning = mock(ClientMetadataProvisioning.class);
        bootstrap.setClientMetadataProvisioning(clientMetadataProvisioning);

        Map<String, Object> map = createClientMap("foo");
        BaseClientDetails output = new BaseClientDetails("foo", "none", "openid", "authorization_code,refresh_token", "uaa.none", "http://localhost/callback");
        output.setClientSecret("bar");
        bootstrap.setAutoApproveClients(Arrays.asList("foo", "non-existent-client"));

        when(clientMetadataProvisioning.update(any(ClientMetadata.class))).thenReturn(new ClientMetadata());
        doReturn(output).when(clientRegistrationService).loadClientByClientId(eq("foo"));
        bootstrap.setClients(Collections.singletonMap((String) map.get("id"), map));

        BaseClientDetails expectedAdd = new BaseClientDetails(output);

        bootstrap.afterPropertiesSet();
        verify(clientRegistrationService).addClientDetails(expectedAdd);
        BaseClientDetails expectedUpdate = new BaseClientDetails(expectedAdd);
        expectedUpdate.setAdditionalInformation(Collections.singletonMap(ClientConstants.AUTO_APPROVE, true));
        verify(clientRegistrationService).updateClientDetails(expectedUpdate);
    }

    @Test
    public void testOverrideClient() throws Exception {
        ClientMetadataProvisioning clientMetadataProvisioning = mock(ClientMetadataProvisioning.class);
        bootstrap.setClientMetadataProvisioning(clientMetadataProvisioning);

        BaseClientDetails foo = new BaseClientDetails("foo", "", "openid", "client_credentials,password", "uaa.none");
        foo.setClientSecret("secret");
        clientRegistrationService.addClientDetails(foo);
        reset(clientRegistrationService);
        Map<String, Object> map = new HashMap<>();
        map.put("secret", "bar");
        map.put("override", true);
        map.put("authorized-grant-types", "client_credentials");
        bootstrap.setClients(Collections.singletonMap("foo", map));
        when(clientMetadataProvisioning.update(any(ClientMetadata.class))).thenReturn(new ClientMetadata());

        doThrow(new ClientAlreadyExistsException("Planned"))
            .when(clientRegistrationService).addClientDetails(any(ClientDetails.class));
        bootstrap.afterPropertiesSet();
        verify(clientRegistrationService, times(1)).addClientDetails(any(ClientDetails.class));
        ArgumentCaptor<ClientDetails> captor = ArgumentCaptor.forClass(ClientDetails.class);
        verify(clientRegistrationService, times(1)).updateClientDetails(captor.capture());
        verify(clientRegistrationService, times(1)).updateClientSecret("foo", "bar");
        assertEquals(new HashSet(Arrays.asList("client_credentials")), captor.getValue().getAuthorizedGrantTypes());
    }

    @Test
    public void testOverrideClientByDefault() throws Exception {
        ClientMetadataProvisioning clientMetadataProvisioning = mock(ClientMetadataProvisioning.class);
        bootstrap.setClientMetadataProvisioning(clientMetadataProvisioning);
        BaseClientDetails foo = new BaseClientDetails("foo", "", "openid", "client_credentials,password", "uaa.none");
        foo.setClientSecret("secret");
        clientRegistrationService.addClientDetails(foo);
        reset(clientRegistrationService);

        Map<String, Object> map = new HashMap<>();
        map.put("secret", "bar");
        map.put("redirect-uri", "http://localhost/callback");
        map.put("authorized-grant-types","client_credentials");
        bootstrap.setClients(Collections.singletonMap("foo", map));
        when(clientMetadataProvisioning.update(any(ClientMetadata.class))).thenReturn(new ClientMetadata());
        doThrow(new ClientAlreadyExistsException("Planned")).when(clientRegistrationService).addClientDetails(
                        any(ClientDetails.class));
        bootstrap.afterPropertiesSet();
        verify(clientRegistrationService, times(1)).addClientDetails(any(ClientDetails.class));
        verify(clientRegistrationService, times(1)).updateClientDetails(any(ClientDetails.class));
        verify(clientRegistrationService, times(1)).updateClientSecret("foo", "bar");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testOverrideClientWithYaml() throws Exception {
        ClientMetadataProvisioning clientMetadataProvisioning = mock(ClientMetadataProvisioning.class);
        bootstrap.setClientMetadataProvisioning(clientMetadataProvisioning);

        @SuppressWarnings("rawtypes")
        Map fooBeforeClient = new Yaml().loadAs("id: foo\noverride: true\nsecret: somevalue\n"
                        + "access-token-validity: 100\nredirect-uri: http://localhost/callback\n"
                        + "authorized-grant-types: client_credentials", Map.class);
        @SuppressWarnings("rawtypes")
        Map barBeforeClient = new Yaml().loadAs("id: bar\noverride: true\nsecret: somevalue\n"
                        + "access-token-validity: 100\nredirect-uri: http://localhost/callback\n"
                        + "authorized-grant-types: client_credentials", Map.class);
        @SuppressWarnings("rawtypes")
        Map clients = new HashMap();
        clients.put("foo", fooBeforeClient);
        clients.put("bar", barBeforeClient);
        bootstrap.setClients(clients);
        bootstrap.afterPropertiesSet();

        Map fooUpdateClient = new HashMap(fooBeforeClient);
        fooUpdateClient.put("secret","bar");
        Map barUpdateClient = new HashMap(fooBeforeClient);
        barUpdateClient.put("secret","bar");
        clients = new HashMap();
        clients.put("foo", fooUpdateClient);
        clients.put("bar", barUpdateClient);
        bootstrap.setClients(clients);

        reset(clientRegistrationService);
        when(clientMetadataProvisioning.update(any(ClientMetadata.class))).thenReturn(new ClientMetadata());
        doThrow(new ClientAlreadyExistsException("Planned")).when(clientRegistrationService).addClientDetails(
                        any(ClientDetails.class));
        bootstrap.afterPropertiesSet();
        verify(clientRegistrationService, times(2)).addClientDetails(any(ClientDetails.class));
        verify(clientRegistrationService, times(2)).updateClientDetails(any(ClientDetails.class));
        verify(clientRegistrationService, times(1)).updateClientSecret("foo", "bar");
        verify(clientRegistrationService, times(1)).updateClientSecret("bar", "bar");
    }

    @Test
    public void testChangePasswordDuringBootstrap() throws Exception {
        Map<String, Object> map = createClientMap("foo");
        ClientDetails created = doSimpleTest(map);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        ClientDetails details = clientRegistrationService.loadClientByClientId("foo");
        assertTrue("Password should match bar:", bootstrap.getPasswordEncoder().matches("bar", details.getClientSecret()));
        map.put("secret", "bar1");
        created = doSimpleTest(map);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        details = clientRegistrationService.loadClientByClientId("foo");
        assertTrue("Password should match bar1:", bootstrap.getPasswordEncoder().matches("bar1", details.getClientSecret()));
        assertFalse("Password should not match bar:", bootstrap.getPasswordEncoder().matches("bar", details.getClientSecret()));
    }

    @Test
    public void testPasswordHashDidNotChangeDuringBootstrap() throws Exception {
        Map<String, Object> map = createClientMap("foo");
        ClientDetails created = doSimpleTest(map);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        ClientDetails details = clientRegistrationService.loadClientByClientId("foo");
        assertTrue("Password should match bar:", bootstrap.getPasswordEncoder().matches("bar", details.getClientSecret()));
        String hash = details.getClientSecret();
        created = doSimpleTest(map);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        details = clientRegistrationService.loadClientByClientId("foo");
        assertTrue("Password should match bar:", bootstrap.getPasswordEncoder().matches("bar", details.getClientSecret()));
        assertEquals("Password hash must not change on an update:", hash, details.getClientSecret());
    }

    @Test
    public void testClientWithoutGrantTypeFails() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorities", "uaa.none");
        exception.expect(InvalidClientDetailsException.class);
        exception.expectMessage("Client must have at least one authorized-grant-type");
        bootstrap.setClients(Collections.singletonMap((String) map.get("id"), map));
        bootstrap.afterPropertiesSet();
    }

    private ClientDetails doSimpleTest(Map<String, Object> map) throws Exception {
        bootstrap.setClients(Collections.singletonMap((String) map.get("id"), map));
        bootstrap.afterPropertiesSet();

        ClientDetails created = clientRegistrationService.loadClientByClientId((String) map.get("id"));
        assertNotNull(created);
        assertSet((String) map.get("scope"), Collections.singleton("uaa.none"), created.getScope(), String.class);
        assertSet((String) map.get("resource-ids"), new HashSet(Arrays.asList("none")), created.getResourceIds(), String.class);

        String authTypes = (String) map.get("authorized-grant-types");
        if (authTypes!=null && authTypes.contains("authorization_code")) {
            authTypes+=",refresh_token";
        }
        assertSet(authTypes, Collections.emptySet(), created.getAuthorizedGrantTypes(), String.class);

        Integer validity = (Integer) map.get("access-token-validity");
        assertEquals(validity, created.getAccessTokenValiditySeconds());
        validity = (Integer) map.get("refresh-token-validity");
        assertEquals(validity, created.getRefreshTokenValiditySeconds());

        assertSet((String) map.get("authorities"), Collections.emptySet(), created.getAuthorities(), GrantedAuthority.class);

        Map<String, Object> info = new HashMap<>(map);

        for (String key : Arrays.asList("resource-ids", "scope", "authorized-grant-types", "authorities",
                "redirect-uri", "secret", "id", "override", "access-token-validity",
                "refresh-token-validity")) {
            info.remove(key);
        }
        for (Map.Entry<String,Object> entry : info.entrySet()) {
            assertTrue("Client should contain additional information key:"+ entry.getKey(), created.getAdditionalInformation().containsKey(entry.getKey()));
            if (entry.getValue()!=null) {
                assertEquals(entry.getValue(), created.getAdditionalInformation().get(entry.getKey()));
            }
        }

        return created;

    }

    private void assertSet(String expectedValue, Collection defaultValueIfNull, Collection actualValue, Class<?> type) {
        Collection assertScopes =  defaultValueIfNull;
        if (expectedValue!=null) {
            if (String.class.equals(type)) {
                assertScopes = StringUtils.commaDelimitedListToSet(expectedValue);
            } else {
                assertScopes = AuthorityUtils.commaSeparatedStringToAuthorityList(expectedValue);
            }
        }
        assertEquals(assertScopes, actualValue);
    }

}
