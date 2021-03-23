package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
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

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class ClientAdminBootstrapTests {

    private ClientAdminBootstrap clientAdminBootstrap;
    private MultitenantJdbcClientDetailsService multitenantJdbcClientDetailsService;
    private ClientMetadataProvisioning clientMetadataProvisioning;
    private ApplicationEventPublisher mockApplicationEventPublisher;
    private RandomValueStringGenerator randomValueStringGenerator;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private String autoApproveId;
    private Map<String, Map<String, Object>> clients;

    @BeforeEach
    void setUpClientAdminTests() {
        randomValueStringGenerator = new RandomValueStringGenerator();

        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());

        multitenantJdbcClientDetailsService = spy(new MultitenantJdbcClientDetailsService(jdbcTemplate, mockIdentityZoneManager, passwordEncoder));

        clientMetadataProvisioning = new JdbcClientMetadataProvisioning(multitenantJdbcClientDetailsService, jdbcTemplate);

        autoApproveId = "autoapprove-" + randomValueStringGenerator.generate().toLowerCase();
        clients = new HashMap<>();

        clientAdminBootstrap = new ClientAdminBootstrap(
                passwordEncoder,
                multitenantJdbcClientDetailsService,
                clientMetadataProvisioning,
                true,
                clients,
                Collections.singleton(autoApproveId),
                Collections.emptySet(),
                null);

        mockApplicationEventPublisher = mock(ApplicationEventPublisher.class);
        clientAdminBootstrap.setApplicationEventPublisher(mockApplicationEventPublisher);
    }

    @Nested
    @WithDatabaseContext
    class WithNullClients {
        @BeforeEach
        void setUp() {
            clientAdminBootstrap = new ClientAdminBootstrap(
                    passwordEncoder,
                    multitenantJdbcClientDetailsService,
                    clientMetadataProvisioning,
                    true,
                    null,
                    Collections.emptySet(),
                    Collections.emptySet(),
                    null);
        }

        @Test
        void doesNotAddClients() {
            reset(multitenantJdbcClientDetailsService);

            clientAdminBootstrap.afterPropertiesSet();

            verifyZeroInteractions(multitenantJdbcClientDetailsService);
        }
    }

    @Test
    void simpleAddClient() throws Exception {
        simpleAddClient("foo", clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
    }

    @Nested
    @WithDatabaseContext
    class WithClientsToDelete {

        private String clientIdToDelete;

        @BeforeEach
        void setUp() {
            clientIdToDelete = "clientIdToDelete" + randomValueStringGenerator.generate();

            clientAdminBootstrap = new ClientAdminBootstrap(
                    passwordEncoder,
                    multitenantJdbcClientDetailsService,
                    clientMetadataProvisioning,
                    true,
                    clients,
                    Collections.singleton(clientIdToDelete),
                    Collections.singleton(clientIdToDelete),
                    null);
            clientAdminBootstrap.setApplicationEventPublisher(mockApplicationEventPublisher);
        }

        @Test
        void clientSlatedForDeletionDoesNotGetInserted() {
            clientAdminBootstrap.afterPropertiesSet();

            verify(multitenantJdbcClientDetailsService, never()).addClientDetails(any(), anyString());
            verify(multitenantJdbcClientDetailsService, never()).updateClientDetails(any(), anyString());
            verify(multitenantJdbcClientDetailsService, never()).updateClientSecret(any(), any(), anyString());
        }

        @Test
        void deleteFromYamlExistingClient() throws Exception {
            createClientInDb(clientIdToDelete, multitenantJdbcClientDetailsService);
            simpleAddClient(clientIdToDelete, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
            verifyZeroInteractions(mockApplicationEventPublisher);

            clientAdminBootstrap.onApplicationEvent(null);

            ArgumentCaptor<EntityDeletedEvent> captor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
            verify(mockApplicationEventPublisher, times(1)).publishEvent(captor.capture());
            assertNotNull(captor.getValue());
            assertEquals(clientIdToDelete, captor.getValue().getObjectId());
            assertEquals(clientIdToDelete, ((ClientDetails) captor.getValue().getDeleted()).getClientId());
            assertSame(SystemAuthentication.SYSTEM_AUTHENTICATION, captor.getValue().getAuthentication());
            assertNotNull(captor.getValue().getAuditEvent());
        }

        @Test
        void deleteFromYamlNonExistingClient() {
            clientAdminBootstrap.onApplicationEvent(new ContextRefreshedEvent(mock(ApplicationContext.class)));

            verify(multitenantJdbcClientDetailsService, times(1)).loadClientByClientId(clientIdToDelete, "uaa");
            verifyZeroInteractions(mockApplicationEventPublisher);
        }
    }

    @Test
    void noRegisteredRedirectUrlForAuthCode() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        assertThrows(InvalidClientDetailsException.class, () ->
                doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients));
    }

    @Test
    void noRegisteredRedirectUrlForImplicit() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_IMPLICIT);
        map.put("authorities", "uaa.none");
        assertThrows(InvalidClientDetailsException.class, () ->
                doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients));
    }

    @Test
    void redirectUrlNotRequired() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorities", "uaa.none");
        for (String grantType : Arrays.asList("password", "client_credentials", GRANT_TYPE_SAML2_BEARER, GRANT_TYPE_JWT_BEARER, GRANT_TYPE_USER_TOKEN, GRANT_TYPE_REFRESH_TOKEN)) {
            map.put("authorized-grant-types", grantType);
            doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        }
    }

    @Test
    void simpleAddClientWithSignupSuccessRedirectUrl() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        map.put("signup_redirect_url", "callback_url");
        ClientDetails clientDetails = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertTrue(clientDetails.getRegisteredRedirectUri().contains("callback_url"));
    }

    @Test
    void clientMetadata_getsBootstrapped() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("show-on-homepage", true);
        map.put("app-launch-url", "http://takemetothispage.com");
        map.put("app-icon", "bAsE64encODEd/iMAgE=");
        map.put("redirect-uri", "http://localhost/callback");
        map.put("authorized-grant-types", "client_credentials");
        clients.put("foo", map);

        clientAdminBootstrap.afterPropertiesSet();

        ClientMetadata clientMetadata = clientMetadataProvisioning.retrieve("foo", "uaa");
        assertTrue(clientMetadata.isShowOnHomePage());
        assertEquals("http://takemetothispage.com", clientMetadata.getAppLaunchUrl().toString());
        assertEquals("bAsE64encODEd/iMAgE=", clientMetadata.getAppIcon());
    }

    @Test
    void additionalInformation() throws Exception {
        List<String> idps = Arrays.asList("idp1", "idp1");
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        map.put("signup_redirect_url", "callback_url");
        map.put("change_email_redirect_url", "change_email_url");
        map.put(ClientConstants.ALLOWED_PROVIDERS, idps);
        ClientDetails created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertEquals(idps, created.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS));
        assertTrue(created.getRegisteredRedirectUri().contains("callback_url"));
        assertTrue(created.getRegisteredRedirectUri().contains("change_email_url"));
    }

    @Test
    void simpleAddClientWithChangeEmailRedirectUrl() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        map.put("change_email_redirect_url", "change_email_callback_url");
        ClientDetails created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertTrue(created.getRegisteredRedirectUri().contains("change_email_callback_url"));
    }

    @Nested
    @WithDatabaseContext
    class WithMockClientMetadataProvisioning {

        private ClientMetadataProvisioning mockClientMetadataProvisioning;

        @BeforeEach
        void setUp() {
            mockClientMetadataProvisioning = mock(ClientMetadataProvisioning.class);
            clientAdminBootstrap = new ClientAdminBootstrap(
                    passwordEncoder,
                    multitenantJdbcClientDetailsService,
                    mockClientMetadataProvisioning,
                    true,
                    clients,
                    Collections.singleton(autoApproveId),
                    Collections.emptySet(),
                    null);
            when(mockClientMetadataProvisioning.update(any(ClientMetadata.class), anyString())).thenReturn(new ClientMetadata());
        }

        @Test
        void simpleAddClientWithAutoApprove() {
            Map<String, Object> map = createClientMap(autoApproveId);
            BaseClientDetails output = new BaseClientDetails(autoApproveId, "none", "openid", "authorization_code,refresh_token", "uaa.none", "http://localhost/callback");
            output.setClientSecret("bar");

            doReturn(output).when(multitenantJdbcClientDetailsService).loadClientByClientId(eq(autoApproveId), anyString());
            clients.put((String) map.get("id"), map);

            BaseClientDetails expectedAdd = new BaseClientDetails(output);

            clientAdminBootstrap.afterPropertiesSet();
            verify(multitenantJdbcClientDetailsService).addClientDetails(expectedAdd, "uaa");
            BaseClientDetails expectedUpdate = new BaseClientDetails(expectedAdd);
            expectedUpdate.setAdditionalInformation(Collections.singletonMap(ClientConstants.AUTO_APPROVE, true));
            verify(multitenantJdbcClientDetailsService).updateClientDetails(expectedUpdate, "uaa");
        }

        @Test
        void overrideClient() {
            String clientId = randomValueStringGenerator.generate();
            BaseClientDetails foo = new BaseClientDetails(clientId, "", "openid", "client_credentials,password", "uaa.none");
            foo.setClientSecret("secret");
            multitenantJdbcClientDetailsService.addClientDetails(foo);
            reset(multitenantJdbcClientDetailsService);
            Map<String, Object> map = new HashMap<>();
            map.put("secret", "bar");
            map.put("override", true);
            map.put("authorized-grant-types", "client_credentials");
            clients.put(clientId, map);

            doThrow(new ClientAlreadyExistsException("Planned"))
                    .when(multitenantJdbcClientDetailsService).addClientDetails(any(ClientDetails.class), anyString());
            clientAdminBootstrap.afterPropertiesSet();
            verify(multitenantJdbcClientDetailsService, times(1)).addClientDetails(any(ClientDetails.class), anyString());
            ArgumentCaptor<ClientDetails> captor = ArgumentCaptor.forClass(ClientDetails.class);
            verify(multitenantJdbcClientDetailsService, times(1)).updateClientDetails(captor.capture(), anyString());
            verify(multitenantJdbcClientDetailsService, times(1)).updateClientSecret(clientId, "bar", "uaa");
            assertEquals(new HashSet(Collections.singletonList("client_credentials")), captor.getValue().getAuthorizedGrantTypes());
        }

        @Nested
        @WithDatabaseContext
        class WithFalseDefaultOverride {

            @BeforeEach
            void setUp() {
                clientAdminBootstrap = new ClientAdminBootstrap(
                        passwordEncoder,
                        multitenantJdbcClientDetailsService,
                        mockClientMetadataProvisioning,
                        false,
                        clients,
                        Collections.singleton(autoApproveId),
                        Collections.emptySet(),
                        null
                );
            }

            @Test
            void overrideClient_usingDefaultOverride() {
                String clientId = randomValueStringGenerator.generate();
                BaseClientDetails foo = new BaseClientDetails(clientId, "", "openid", "client_credentials,password", "uaa.none");
                foo.setClientSecret("secret");
                multitenantJdbcClientDetailsService.addClientDetails(foo);
                reset(multitenantJdbcClientDetailsService);
                Map<String, Object> map = new HashMap<>();
                map.put("secret", "bar");
                map.put("override", null);
                map.put("authorized-grant-types", "client_credentials");
                clients.put(clientId, map);

                doThrow(new ClientAlreadyExistsException("Planned"))
                        .when(multitenantJdbcClientDetailsService).addClientDetails(any(ClientDetails.class), anyString());
                clientAdminBootstrap.afterPropertiesSet();
                verify(multitenantJdbcClientDetailsService, times(1)).addClientDetails(any(ClientDetails.class), anyString());
                verify(multitenantJdbcClientDetailsService, never()).updateClientDetails(any(), any());
                verify(multitenantJdbcClientDetailsService, never()).updateClientSecret(any(), any(), any());
            }
        }

        @Test
        void overrideClientWithEmptySecret() {
            String clientId = randomValueStringGenerator.generate();
            BaseClientDetails foo = new BaseClientDetails(clientId, "", "openid", "client_credentials,password", "uaa.none");
            foo.setClientSecret("secret");
            multitenantJdbcClientDetailsService.addClientDetails(foo);

            reset(multitenantJdbcClientDetailsService);

            Map<String, Object> map = new HashMap<>();
            map.put("secret", null);
            map.put("override", true);
            map.put("authorized-grant-types", "client_credentials");
            clients.put(clientId, map);

            doThrow(new ClientAlreadyExistsException("Planned"))
                    .when(multitenantJdbcClientDetailsService).addClientDetails(any(ClientDetails.class), anyString());
            clientAdminBootstrap.afterPropertiesSet();
            verify(multitenantJdbcClientDetailsService, times(1)).addClientDetails(any(ClientDetails.class), anyString());
            ArgumentCaptor<ClientDetails> captor = ArgumentCaptor.forClass(ClientDetails.class);
            verify(multitenantJdbcClientDetailsService, times(1)).updateClientDetails(captor.capture(), anyString());
            verify(multitenantJdbcClientDetailsService, times(1)).updateClientSecret(clientId, "", "uaa");
            assertEquals(new HashSet(Collections.singletonList("client_credentials")), captor.getValue().getAuthorizedGrantTypes());
        }

        @Test
        void overrideClientByDefault() {
            String clientId = randomValueStringGenerator.generate();
            BaseClientDetails foo = new BaseClientDetails(clientId, "", "openid", "client_credentials,password", "uaa.none");
            foo.setClientSecret("secret");
            multitenantJdbcClientDetailsService.addClientDetails(foo);
            reset(multitenantJdbcClientDetailsService);

            Map<String, Object> map = new HashMap<>();
            map.put("secret", "bar");
            map.put("redirect-uri", "http://localhost/callback");
            map.put("authorized-grant-types", "client_credentials");

            clients.put(clientId, map);
            doThrow(new ClientAlreadyExistsException("Planned")).when(multitenantJdbcClientDetailsService)
                    .addClientDetails(
                            any(ClientDetails.class),
                            anyString()
                    );
            clientAdminBootstrap.afterPropertiesSet();
            verify(multitenantJdbcClientDetailsService, times(1)).addClientDetails(any(ClientDetails.class), anyString());
            verify(multitenantJdbcClientDetailsService, times(1)).updateClientDetails(any(ClientDetails.class), anyString());
            verify(multitenantJdbcClientDetailsService, times(1)).updateClientSecret(clientId, "bar", "uaa");
        }

        @Test
        @SuppressWarnings("unchecked")
        void overrideClientWithYaml() {
            @SuppressWarnings("rawtypes")
            Map fooBeforeClient = new Yaml().loadAs("id: foo\noverride: true\nsecret: somevalue\n"
                    + "access-token-validity: 100\nredirect-uri: http://localhost/callback\n"
                    + "authorized-grant-types: client_credentials", Map.class);
            @SuppressWarnings("rawtypes")
            Map barBeforeClient = new Yaml().loadAs("id: bar\noverride: true\nsecret: somevalue\n"
                    + "access-token-validity: 100\nredirect-uri: http://localhost/callback\n"
                    + "authorized-grant-types: client_credentials", Map.class);
            clients.put("foo", fooBeforeClient);
            clients.put("bar", barBeforeClient);
            clientAdminBootstrap.afterPropertiesSet();

            Map fooUpdateClient = new HashMap(fooBeforeClient);
            fooUpdateClient.put("secret", "bar");
            Map barUpdateClient = new HashMap(fooBeforeClient);
            barUpdateClient.put("secret", "bar");
            clients.put("foo", fooUpdateClient);
            clients.put("bar", barUpdateClient);

            reset(multitenantJdbcClientDetailsService);
            doThrow(new ClientAlreadyExistsException("Planned")).when(multitenantJdbcClientDetailsService).addClientDetails(
                    any(ClientDetails.class), anyString());
            clientAdminBootstrap.afterPropertiesSet();
            verify(multitenantJdbcClientDetailsService, times(2)).addClientDetails(any(ClientDetails.class), anyString());
            verify(multitenantJdbcClientDetailsService, times(2)).updateClientDetails(any(ClientDetails.class), anyString());
            verify(multitenantJdbcClientDetailsService, times(1)).updateClientSecret("foo", "bar", "uaa");
            verify(multitenantJdbcClientDetailsService, times(1)).updateClientSecret("bar", "bar", "uaa");
        }
    }

    @Test
    void changePasswordDuringBootstrap() throws Exception {
        Map<String, Object> map = createClientMap("foo");
        ClientDetails created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        ClientDetails details = multitenantJdbcClientDetailsService.loadClientByClientId("foo");
        assertTrue(passwordEncoder.matches("bar", details.getClientSecret()), "Password should match bar:");
        map.put("secret", "bar1");
        created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        details = multitenantJdbcClientDetailsService.loadClientByClientId("foo");
        assertTrue(passwordEncoder.matches("bar1", details.getClientSecret()), "Password should match bar1:");
        assertFalse(passwordEncoder.matches("bar", details.getClientSecret()), "Password should not match bar:");
    }

    @Test
    void passwordHashDidNotChangeDuringBootstrap() throws Exception {
        Map<String, Object> map = createClientMap("foo");
        ClientDetails created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        ClientDetails details = multitenantJdbcClientDetailsService.loadClientByClientId("foo");
        assertTrue(passwordEncoder.matches("bar", details.getClientSecret()), "Password should match bar:");
        String hash = details.getClientSecret();
        created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        details = multitenantJdbcClientDetailsService.loadClientByClientId("foo");
        assertTrue(passwordEncoder.matches("bar", details.getClientSecret()), "Password should match bar:");
        assertEquals(hash, details.getClientSecret(), "Password hash must not change on an update:");
    }

    @Test
    void clientWithoutGrantTypeFails() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorities", "uaa.none");
        clients.put((String) map.get("id"), map);

        assertThrowsWithMessageThat(InvalidClientDetailsException.class,
                () -> clientAdminBootstrap.afterPropertiesSet(),
                containsString("Client must have at least one authorized-grant-type")
        );
    }

    private static ClientDetails doSimpleTest(
            final Map<String, Object> map,
            final ClientAdminBootstrap clientAdminBootstrap,
            final MultitenantJdbcClientDetailsService clientRegistrationService,
            final Map<String, Map<String, Object>> clients) {
        clients.put((String) map.get("id"), map);
        clientAdminBootstrap.afterPropertiesSet();

        ClientDetails created = clientRegistrationService.loadClientByClientId((String) map.get("id"));
        assertNotNull(created);
        assertSet((String) map.get("scope"), Collections.singleton("uaa.none"), created.getScope(), String.class);
        assertSet((String) map.get("resource-ids"), new HashSet(Collections.singletonList("none")), created.getResourceIds(), String.class);

        String authTypes = (String) map.get("authorized-grant-types");
        if (authTypes != null && authTypes.contains(GRANT_TYPE_AUTHORIZATION_CODE)) {
            authTypes += ",refresh_token";
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
        for (Map.Entry<String, Object> entry : info.entrySet()) {
            assertTrue(created.getAdditionalInformation().containsKey(entry.getKey()), "Client should contain additional information key:" + entry.getKey());
            if (entry.getValue() != null) {
                assertEquals(entry.getValue(), created.getAdditionalInformation().get(entry.getKey()));
            }
        }

        return created;
    }

    private static void assertSet(
            final String expectedValue,
            final Collection defaultValueIfNull,
            final Collection actualValue,
            final Class<?> type) {
        Collection assertScopes = defaultValueIfNull;
        if (expectedValue != null) {
            if (String.class.equals(type)) {
                assertScopes = StringUtils.commaDelimitedListToSet(expectedValue);
            } else {
                assertScopes = AuthorityUtils.commaSeparatedStringToAuthorityList(expectedValue);
            }
        }
        assertEquals(assertScopes, actualValue);
    }

    private static void simpleAddClient(
            final String clientId,
            final ClientAdminBootstrap bootstrap,
            final MultitenantJdbcClientDetailsService clientRegistrationService,
            final Map<String, Map<String, Object>> clients) throws Exception {
        Map<String, Object> map = createClientMap(clientId);
        ClientDetails created = doSimpleTest(map, bootstrap, clientRegistrationService, clients);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
    }

    private static Map<String, Object> createClientMap(final String clientId) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", clientId);
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        map.put("redirect-uri", "http://localhost/callback");
        return map;
    }

    private static void createClientInDb(
            final String clientId,
            final MultitenantJdbcClientDetailsService multitenantJdbcClientDetailsService) {
        BaseClientDetails foo = new BaseClientDetails(clientId, "none", "openid", "authorization_code,refresh_token", "uaa.none");
        foo.setClientSecret("secret");
        foo.setRegisteredRedirectUri(Collections.singleton("http://localhost/callback"));
        multitenantJdbcClientDetailsService.addClientDetails(foo);
    }


}
