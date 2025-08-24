package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
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
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.yaml.snakeyaml.Yaml;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
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
import static org.mockito.Mockito.verifyNoInteractions;
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

    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;

    private String autoApproveId;

    private String allowPublicId;
    private Map<String, Map<String, Object>> clients;

    @BeforeEach
    void setUpClientAdminTests() {
        randomValueStringGenerator = new RandomValueStringGenerator();

        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());

        multitenantJdbcClientDetailsService = spy(new MultitenantJdbcClientDetailsService(namedJdbcTemplate, mockIdentityZoneManager, passwordEncoder));

        clientMetadataProvisioning = new JdbcClientMetadataProvisioning(multitenantJdbcClientDetailsService, jdbcTemplate);

        autoApproveId = "autoapprove-" + randomValueStringGenerator.generate().toLowerCase();
        allowPublicId = "public-" + randomValueStringGenerator.generate().toLowerCase();
        clients = new HashMap<>();

        clientAdminBootstrap = new ClientAdminBootstrap(
                passwordEncoder,
                multitenantJdbcClientDetailsService,
                clientMetadataProvisioning,
                true,
                clients,
                Collections.singleton(autoApproveId),
                Collections.emptySet(),
                null,
                Collections.singleton(allowPublicId));

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
                    null,
                    Collections.emptySet());
        }

        @Test
        void doesNotAddClients() {
            reset(multitenantJdbcClientDetailsService);

            clientAdminBootstrap.afterPropertiesSet();

            verifyNoInteractions(multitenantJdbcClientDetailsService);
        }
    }

    @Test
    void simpleAddClient() {
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
                    null, Collections.singleton(clientIdToDelete));
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
        void deleteFromYamlExistingClient() {
            createClientInDb(clientIdToDelete, multitenantJdbcClientDetailsService);
            simpleAddClient(clientIdToDelete, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
            verifyNoInteractions(mockApplicationEventPublisher);

            clientAdminBootstrap.onApplicationEvent(null);

            ArgumentCaptor<EntityDeletedEvent> captor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
            verify(mockApplicationEventPublisher, times(1)).publishEvent(captor.capture());
            assertThat(captor.getValue()).isNotNull();
            assertThat(captor.getValue().getObjectId()).isEqualTo(clientIdToDelete);
            assertThat(((ClientDetails) captor.getValue().getDeleted()).getClientId()).isEqualTo(clientIdToDelete);
            assertThat(captor.getValue().getAuthentication()).isSameAs(SystemAuthentication.SYSTEM_AUTHENTICATION);
            assertThat(captor.getValue().getAuditEvent()).isNotNull();
        }

        @Test
        void deleteFromYamlNonExistingClient() {
            clientAdminBootstrap.onApplicationEvent(new ContextRefreshedEvent(mock(ApplicationContext.class)));

            verify(multitenantJdbcClientDetailsService, times(1)).loadClientByClientId(clientIdToDelete, "uaa");
            verifyNoInteractions(mockApplicationEventPublisher);
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
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() ->
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
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() ->
                doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients));
    }

    @Test
    void redirectUrlNotRequired() {
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
    void simpleAddClientWithSignupSuccessRedirectUrl() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        map.put("signup_redirect_url", "callback_url");
        ClientDetails clientDetails = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertThat(clientDetails.getRegisteredRedirectUri()).contains("callback_url");
    }

    @Test
    void simpleAddClientWithJwksUri() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo-jwks-uri");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        map.put("redirect-uri", "http://localhost/callback");
        map.put("jwks_uri", "https://localhost:8080/uaa");
        UaaClientDetails clientDetails = (UaaClientDetails) doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertThat(clientDetails.getClientJwtConfig()).isNotNull();
    }

    @Test
    void simpleAddClientWithJwkSet() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo-jwks");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        map.put("redirect-uri", "http://localhost/callback");
        map.put("jwks", "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}");
        UaaClientDetails clientDetails = (UaaClientDetails) doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertThat(clientDetails.getClientJwtConfig()).isNotNull();
    }

    @Test
    void simpleInvalidClientWithJwkSet() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo-jwks");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        map.put("redirect-uri", "http://localhost/callback");
        map.put("jwks", "invalid");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients));
    }

    @Test
    void simpleAddClientWithClientJwtCredendial() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo-jwks");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        map.put("redirect-uri", "http://localhost/callback");
        map.put("jwt_creds", "[{\"iss\":\"http://localhost:8080/uaa/oauth/token\",\"sub\":\"foo-jwt\"}]");
        UaaClientDetails clientDetails = (UaaClientDetails) doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertThat(clientDetails.getClientJwtConfig()).isNotNull();
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
        assertThat(clientMetadata.isShowOnHomePage()).isTrue();
        assertThat(clientMetadata.getAppLaunchUrl()).hasToString("http://takemetothispage.com");
        assertThat(clientMetadata.getAppIcon()).isEqualTo("bAsE64encODEd/iMAgE=");
    }

    @Test
    void additionalInformation() {
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
        assertThat(created.getAdditionalInformation()).containsEntry(ClientConstants.ALLOWED_PROVIDERS, idps);
        assertThat(created.getRegisteredRedirectUri()).contains("callback_url", "change_email_url");
    }

    @Test
    void simpleAddClientWithChangeEmailRedirectUrl() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorized-grant-types", GRANT_TYPE_AUTHORIZATION_CODE);
        map.put("authorities", "uaa.none");
        map.put("change_email_redirect_url", "change_email_callback_url");
        ClientDetails created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertThat(created.getRegisteredRedirectUri()).contains("change_email_callback_url");
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
                    null, Collections.singleton(allowPublicId));
            when(mockClientMetadataProvisioning.update(any(ClientMetadata.class), anyString())).thenReturn(new ClientMetadata());
        }

        @Test
        void simpleAddClientWithAutoApprove() {
            Map<String, Object> map = createClientMap(autoApproveId);
            UaaClientDetails output = new UaaClientDetails(autoApproveId, "none", "openid", "authorization_code,refresh_token", "uaa.none", "http://localhost/callback");
            output.setClientSecret("bar");

            doReturn(output).when(multitenantJdbcClientDetailsService).loadClientByClientId(eq(autoApproveId), anyString());
            clients.put((String) map.get("id"), map);

            UaaClientDetails expectedAdd = new UaaClientDetails(output);

            clientAdminBootstrap.afterPropertiesSet();
            verify(multitenantJdbcClientDetailsService).addClientDetails(expectedAdd, "uaa");
            UaaClientDetails expectedUpdate = new UaaClientDetails(expectedAdd);
            expectedUpdate.setAdditionalInformation(Collections.singletonMap(ClientConstants.AUTO_APPROVE, true));
            verify(multitenantJdbcClientDetailsService).updateClientDetails(expectedUpdate, "uaa");
        }

        @Test
        void simpleAddClientWithAllowPublic() {
            Map<String, Object> map = createClientMap(allowPublicId);
            UaaClientDetails output = new UaaClientDetails(allowPublicId, "none", "openid", "authorization_code,refresh_token", "uaa.none", "http://localhost/callback");
            output.setClientSecret("bar");

            doReturn(output).when(multitenantJdbcClientDetailsService).loadClientByClientId(eq(allowPublicId), anyString());
            clients.put((String) map.get("id"), map);

            UaaClientDetails expectedAdd = new UaaClientDetails(output);

            clientAdminBootstrap.afterPropertiesSet();
            UaaClientDetails expectedUpdate = new UaaClientDetails(expectedAdd);
            expectedUpdate.setAdditionalInformation(Collections.singletonMap(ClientConstants.ALLOW_PUBLIC, true));
            verify(multitenantJdbcClientDetailsService, times(1)).updateClientDetails(expectedUpdate, "uaa");
        }

        @Test
        void simpleAddClientWithAllowPublicNoClient() {
            Map<String, Object> map = createClientMap(allowPublicId);
            UaaClientDetails output = new UaaClientDetails(allowPublicId, "none", "openid", "authorization_code,refresh_token", "uaa.none", "http://localhost/callback");
            output.setClientSecret("bar");

            doThrow(new NoSuchClientException(allowPublicId)).when(multitenantJdbcClientDetailsService).loadClientByClientId(eq(allowPublicId), anyString());
            clients.put((String) map.get("id"), map);

            clientAdminBootstrap.afterPropertiesSet();
            verify(multitenantJdbcClientDetailsService, never()).updateClientDetails(any(), any());
        }

        @Test
        void overrideClient() {
            String clientId = randomValueStringGenerator.generate();
            UaaClientDetails foo = new UaaClientDetails(clientId, "", "openid", "client_credentials,password", "uaa.none");
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
            assertThat(captor.getValue().getAuthorizedGrantTypes()).isEqualTo(new HashSet<>(Collections.singletonList("client_credentials")));
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
                        null, Collections.singleton(allowPublicId));
            }

            @Test
            void overrideClient_usingDefaultOverride() {
                String clientId = randomValueStringGenerator.generate();
                UaaClientDetails foo = new UaaClientDetails(clientId, "", "openid", "client_credentials,password", "uaa.none");
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
            UaaClientDetails foo = new UaaClientDetails(clientId, "", "openid", "client_credentials,password", "uaa.none");
            foo.setClientSecret("secret");
            multitenantJdbcClientDetailsService.addClientDetails(foo);

            reset(multitenantJdbcClientDetailsService);

            Map<String, Object> map = new HashMap<>();
            map.put("secret", "");
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
            assertThat(captor.getValue().getAuthorizedGrantTypes()).isEqualTo(new HashSet<>(Collections.singletonList("client_credentials")));
        }

        @Test
        void doNotOverrideClientWithNullSecret() {
            String clientId = randomValueStringGenerator.generate();
            UaaClientDetails foo = new UaaClientDetails(clientId, "", "openid", "client_credentials,password", "uaa.none");
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
            verify(multitenantJdbcClientDetailsService, times(1)).updateClientSecret(clientId, null, "uaa");
            assertThat(captor.getValue().getAuthorizedGrantTypes()).isEqualTo(new HashSet<>(Collections.singletonList("client_credentials")));
        }

        @Test
        void overrideClientByDefault() {
            String clientId = randomValueStringGenerator.generate();
            UaaClientDetails foo = new UaaClientDetails(clientId, "", "openid", "client_credentials,password", "uaa.none");
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
            Map fooBeforeClient = new Yaml().loadAs("""
                    id: foo
                    override: true
                    secret: somevalue
                    access-token-validity: 100
                    redirect-uri: http://localhost/callback
                    authorized-grant-types: client_credentials""", Map.class);
            @SuppressWarnings("rawtypes")
            Map barBeforeClient = new Yaml().loadAs("""
                    id: bar
                    override: true
                    secret: somevalue
                    access-token-validity: 100
                    redirect-uri: http://localhost/callback
                    authorized-grant-types: client_credentials""", Map.class);
            clients.put("foo", fooBeforeClient);
            clients.put("bar", barBeforeClient);
            clientAdminBootstrap.afterPropertiesSet();

            Map fooUpdateClient = new HashMap<>(fooBeforeClient);
            fooUpdateClient.put("secret", "bar");
            Map barUpdateClient = new HashMap<>(fooBeforeClient);
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
    void changePasswordDuringBootstrap() {
        Map<String, Object> map = createClientMap("foo");
        ClientDetails created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        ClientDetails details = multitenantJdbcClientDetailsService.loadClientByClientId("foo");
        assertThat(passwordEncoder.matches("bar", details.getClientSecret())).as("Password should match bar:").isTrue();
        map.put("secret", "bar1");
        created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        details = multitenantJdbcClientDetailsService.loadClientByClientId("foo");
        assertThat(passwordEncoder.matches("bar1", details.getClientSecret())).as("Password should match bar1:").isTrue();
        assertThat(passwordEncoder.matches("bar", details.getClientSecret())).as("Password should not match bar:").isFalse();
    }

    @Test
    void passwordHashDidNotChangeDuringBootstrap() {
        Map<String, Object> map = createClientMap("foo");
        ClientDetails created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        ClientDetails details = multitenantJdbcClientDetailsService.loadClientByClientId("foo");
        assertThat(passwordEncoder.matches("bar", details.getClientSecret())).as("Password should match bar:").isTrue();
        String hash = details.getClientSecret();
        created = doSimpleTest(map, clientAdminBootstrap, multitenantJdbcClientDetailsService, clients);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        details = multitenantJdbcClientDetailsService.loadClientByClientId("foo");
        assertThat(passwordEncoder.matches("bar", details.getClientSecret())).as("Password should match bar:").isTrue();
        assertThat(details.getClientSecret()).as("Password hash must not change on an update:").isEqualTo(hash);
    }

    @Test
    void clientWithoutGrantTypeFails() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", "foo");
        map.put("secret", "bar");
        map.put("scope", "openid");
        map.put("authorities", "uaa.none");
        clients.put((String) map.get("id"), map);

        assertThatThrownBy(() -> clientAdminBootstrap.afterPropertiesSet())
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("Client must have at least one authorized-grant-type");
    }

    static ClientDetails doSimpleTest(
            final Map<String, Object> map,
            final ClientAdminBootstrap clientAdminBootstrap,
            final MultitenantJdbcClientDetailsService clientRegistrationService,
            final Map<String, Map<String, Object>> clients) {
        clients.put((String) map.get("id"), map);
        clientAdminBootstrap.afterPropertiesSet();

        ClientDetails created = clientRegistrationService.loadClientByClientId((String) map.get("id"));
        assertThat(created).isNotNull();
        assertSet((String) map.get("scope"), Collections.singleton("uaa.none"), created.getScope(), String.class);
        assertSet((String) map.get("resource-ids"), new HashSet<>(Collections.singletonList("none")), created.getResourceIds(), String.class);

        String authTypes = (String) map.get("authorized-grant-types");
        if (authTypes != null && authTypes.contains(GRANT_TYPE_AUTHORIZATION_CODE)) {
            authTypes += ",refresh_token";
        }
        assertSet(authTypes, Collections.emptySet(), created.getAuthorizedGrantTypes(), String.class);

        Integer validity = (Integer) map.get("access-token-validity");
        assertThat(created.getAccessTokenValiditySeconds()).isEqualTo(validity);
        validity = (Integer) map.get("refresh-token-validity");
        assertThat(created.getRefreshTokenValiditySeconds()).isEqualTo(validity);

        assertSet((String) map.get("authorities"), Collections.emptySet(), created.getAuthorities(), GrantedAuthority.class);

        Map<String, Object> info = new HashMap<>(map);

        for (String key : Arrays.asList("resource-ids", "scope", "authorized-grant-types", "authorities",
                "redirect-uri", "secret", "id", "override", "access-token-validity",
                "refresh-token-validity", "jwks", "jwks_uri", "jwt_creds")) {
            info.remove(key);
        }
        for (Map.Entry<String, Object> entry : info.entrySet()) {
            assertThat(created.getAdditionalInformation()).as("Client should contain additional information key:" + entry.getKey()).containsKey(entry.getKey());
            if (entry.getValue() != null) {
                assertThat(created.getAdditionalInformation()).containsEntry(entry.getKey(), entry.getValue());
            }
        }

        return created;
    }

    static void assertSet(
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
        assertThat(actualValue).isEqualTo(assertScopes);
    }

    private static void simpleAddClient(
            final String clientId,
            final ClientAdminBootstrap bootstrap,
            final MultitenantJdbcClientDetailsService clientRegistrationService,
            final Map<String, Map<String, Object>> clients) {
        Map<String, Object> map = createClientMap(clientId);
        ClientDetails created = doSimpleTest(map, bootstrap, clientRegistrationService, clients);
        assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
    }

    static Map<String, Object> createClientMap(final String clientId) {
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
        UaaClientDetails foo = new UaaClientDetails(clientId, "none", "openid", "authorization_code,refresh_token", "uaa.none");
        foo.setClientSecret("secret");
        foo.setRegisteredRedirectUri(Collections.singleton("http://localhost/callback"));
        multitenantJdbcClientDetailsService.addClientDetails(foo);
    }
}
