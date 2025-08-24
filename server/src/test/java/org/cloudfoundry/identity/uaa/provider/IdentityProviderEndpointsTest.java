package org.cloudfoundry.identity.uaa.provider;

import org.apache.commons.lang3.tuple.Pair;
import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UNKNOWN;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class IdentityProviderEndpointsTest {

    @Mock
    private IdentityProviderProvisioning mockIdentityProviderProvisioning;

    @Mock
    private IdentityProviderConfigValidationDelegator mockIdentityProviderConfigValidationDelegator;

    @Mock
    private IdentityZoneManager mockIdentityZoneManager;

    @Mock
    private PlatformTransactionManager mockPlatformTransactionManager;

    @Mock
    private IdentityProviderAliasHandler mockIdpAliasHandler;

    @Mock
    SamlIdentityProviderConfigurator samlConfigurator;

    private IdentityProviderEndpoints identityProviderEndpoints;

    @BeforeEach
    void setup() {
        identityProviderEndpoints = new IdentityProviderEndpoints(
                mockIdentityProviderProvisioning,
                mock(ScimGroupExternalMembershipManager.class),
                mock(ScimGroupProvisioning.class),
                samlConfigurator,
                mockIdentityProviderConfigValidationDelegator,
                mockIdentityZoneManager,
                mockPlatformTransactionManager,
                mockIdpAliasHandler,
                false
        );

        lenient().when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());

        lenient().when(mockIdpAliasHandler.aliasPropertiesAreValid(any(), any()))
                .thenReturn(true);
        lenient().when(mockIdpAliasHandler.ensureConsistencyOfAliasEntity(any(), any()))
                .then(invocationOnMock -> invocationOnMock.getArgument(0));
    }

    IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> getExternalOAuthProvider() {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.addAttributeMapping("user.attribute." + "the_client_id", "cid");
        config.setStoreCustomAttributes(true);

        String urlBase = "http://localhost:8080/";
        try {
            config.setAuthUrl(new URL(urlBase + "/oauth/authorize"));
            config.setTokenUrl(new URL(urlBase + "/oauth/token"));
            config.setTokenKeyUrl(new URL(urlBase + "/token_key"));
            config.setIssuer(urlBase + "/oauth/token");
            config.setUserInfoUrl(new URL(urlBase + "/userinfo"));
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        List<String> requestedScopes = new ArrayList<>();
        requestedScopes.add("openid");
        requestedScopes.add("cloud_controller.read");
        config.setScopes(requestedScopes);
        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");
        identityProvider.setIdentityZoneId(IdentityZone.getUaaZoneId());
        return identityProvider;
    }

    IdentityProvider<LdapIdentityProviderDefinition> getLdapDefinition() {
        String ldapProfile = "ldap-search-and-bind.xml";
        //String ldapProfile = "ldap-search-and-compare.xml";
        String ldapGroup = "ldap-groups-null.xml";
        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        definition.setLdapProfileFile("ldap/" + ldapProfile);
        definition.setLdapGroupFile("ldap/" + ldapGroup);
        definition.setMaxGroupSearchDepth(10);
        definition.setBaseUrl("ldap://localhost");
        definition.setBindUserDn("cn=admin,ou=Users,dc=test,dc=com");
        definition.setBindPassword("adminsecret");
        definition.setSkipSSLVerification(true);
        definition.setTlsConfiguration("none");
        definition.setMailAttributeName("mail");
        definition.setReferral("ignore");

        IdentityProvider<LdapIdentityProviderDefinition> ldapProvider = new IdentityProvider<>();
        ldapProvider.setOriginKey(LDAP);
        ldapProvider.setConfig(definition);
        ldapProvider.setType(LDAP);
        ldapProvider.setId("id");
        return ldapProvider;
    }

    @Test
    void retrieve_oauth_provider_by_id_redacts_password() {
        retrieve_oauth_provider_by_id("", OriginKeys.OAUTH20);
        retrieve_oauth_provider_by_id("", OriginKeys.OIDC10);
    }

    IdentityProvider<LdapIdentityProviderDefinition> retrieve_oauth_provider_by_id(String id, String type) {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> provider = getExternalOAuthProvider();
        provider.setType(type);
        when(mockIdentityProviderProvisioning.retrieve(anyString(), anyString())).thenReturn(provider);
        ResponseEntity<IdentityProvider> oauth = identityProviderEndpoints.retrieveIdentityProvider(id, true);
        assertThat(oauth).isNotNull();
        assertThat(oauth.getStatusCode().value()).isEqualTo(200);
        assertThat(oauth.getBody()).isNotNull();
        assertThat(oauth.getBody().getConfig()).isNotNull();
        assertThat(oauth.getBody().getConfig()).isInstanceOf(AbstractExternalOAuthIdentityProviderDefinition.class);
        assertThat(((AbstractExternalOAuthIdentityProviderDefinition) oauth.getBody().getConfig()).getRelyingPartySecret()).isNull();
        return oauth.getBody();
    }

    @Test
    void retrieve_ldap_provider_by_id_redacts_password() {
        retrieve_ldap_provider_by_id("");
    }

    IdentityProvider<LdapIdentityProviderDefinition> retrieve_ldap_provider_by_id(String id) {
        when(mockIdentityProviderProvisioning.retrieve(anyString(), anyString())).thenReturn(getLdapDefinition());
        ResponseEntity<IdentityProvider> ldap = identityProviderEndpoints.retrieveIdentityProvider(id, true);
        assertThat(ldap).isNotNull();
        assertThat(ldap.getStatusCode().value()).isEqualTo(200);
        assertThat(ldap.getBody()).isNotNull();
        assertThat(ldap.getBody().getConfig()).isNotNull();
        assertThat(ldap.getBody().getConfig()).isInstanceOf(LdapIdentityProviderDefinition.class);
        assertThat(((LdapIdentityProviderDefinition) ldap.getBody().getConfig()).getBindPassword()).isNull();
        return ldap.getBody();
    }

    @Test
    void remove_bind_password() {
        remove_sensitive_data(this::getLdapDefinition,
                LDAP,
                spy -> verify((LdapIdentityProviderDefinition) spy, times(1)).setBindPassword(isNull()));
    }

    @Test
    void remove_client_secret() {
        for (String type : Arrays.asList(OIDC10, OAUTH20)) {
            remove_sensitive_data(this::getExternalOAuthProvider,
                    type,
                    spy -> verify((AbstractExternalOAuthIdentityProviderDefinition) spy, times(1)).setRelyingPartySecret(isNull()));
        }
    }

    void remove_sensitive_data(Supplier<IdentityProvider> getProvider, String type, Consumer<AbstractIdentityProviderDefinition> validator) {
        IdentityProvider provider = getProvider.get();
        AbstractIdentityProviderDefinition spy = Mockito.spy(provider.getConfig());
        provider.setConfig(spy);
        provider.setType(type);
        identityProviderEndpoints.redactSensitiveData(provider);
        validator.accept(spy);

    }

    @Test
    void remove_client_secret_wrong_origin() {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> provider = getExternalOAuthProvider();
        AbstractExternalOAuthIdentityProviderDefinition spy = Mockito.spy(provider.getConfig());
        provider.setConfig(spy);
        provider.setType(UNKNOWN);
        identityProviderEndpoints.redactSensitiveData(provider);
        verify(spy, never()).setRelyingPartySecret(isNull());
    }

    @Test
    void remove_bind_password_non_ldap() {
        IdentityProvider<LdapIdentityProviderDefinition> provider = getLdapDefinition();
        LdapIdentityProviderDefinition spy = Mockito.spy((LdapIdentityProviderDefinition) provider.getConfig());
        provider.setConfig(spy);
        provider.setType(OriginKeys.UNKNOWN);
        identityProviderEndpoints.redactSensitiveData(provider);
        verify(spy, never()).setBindPassword(isNull());
    }

    @Test
    void patch_bind_password() {
        IdentityProvider<LdapIdentityProviderDefinition> provider = getLdapDefinition();
        LdapIdentityProviderDefinition def = provider.getConfig();
        def.setBindPassword(null);
        LdapIdentityProviderDefinition spy = Mockito.spy(def);
        provider.setConfig(spy);
        reset(mockIdentityProviderProvisioning);
        String zoneId = IdentityZone.getUaaZoneId();
        when(mockIdentityProviderProvisioning.retrieve(provider.getId(), zoneId)).thenReturn(getLdapDefinition());
        identityProviderEndpoints.patchSensitiveData(provider.getId(), provider);
        verify(spy, times(1)).setBindPassword(getLdapDefinition().getConfig().getBindPassword());
    }

    @Test
    void patch_client_secret() {
        for (String type : Arrays.asList(OIDC10, OAUTH20)) {
            IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> provider = getExternalOAuthProvider();
            AbstractExternalOAuthIdentityProviderDefinition def = provider.getConfig();
            def.setRelyingPartySecret(null);
            AbstractExternalOAuthIdentityProviderDefinition spy = Mockito.spy(def);
            provider.setConfig(spy);
            provider.setType(type);
            reset(mockIdentityProviderProvisioning);
            String zoneId = IdentityZone.getUaaZoneId();
            when(mockIdentityProviderProvisioning.retrieve(provider.getId(), zoneId)).thenReturn(getExternalOAuthProvider());
            identityProviderEndpoints.patchSensitiveData(provider.getId(), provider);
            verify(spy, times(1)).setRelyingPartySecret(getExternalOAuthProvider().getConfig().getRelyingPartySecret());
        }
    }

    @Test
    void patch_bind_password_non_ldap() {
        IdentityProvider<LdapIdentityProviderDefinition> provider = getLdapDefinition();
        LdapIdentityProviderDefinition spy = Mockito.spy(provider.getConfig());
        provider.setConfig(spy);
        provider.setType(OriginKeys.UNKNOWN);
        identityProviderEndpoints.redactSensitiveData(provider);
        verify(spy, never()).setBindPassword(any());
    }

    @Test
    void retrieve_all_providers_redacts_data() {
        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), anyString()))
                .thenReturn(Arrays.asList(getLdapDefinition(), getExternalOAuthProvider()));
        ResponseEntity<List<IdentityProvider>> ldapList = identityProviderEndpoints.retrieveIdentityProviders("false", true, "");
        assertThat(ldapList).isNotNull();
        assertThat(ldapList.getBody()).isNotNull();
        assertThat(ldapList.getBody()).hasSize(2);
        IdentityProvider<LdapIdentityProviderDefinition> ldap = ldapList.getBody().getFirst();
        assertThat(ldap).isNotNull();
        assertThat(ldap.getConfig()).isNotNull();
        assertThat(ldap.getConfig()).isInstanceOf(LdapIdentityProviderDefinition.class);
        assertThat(ldap.getConfig().getBindPassword()).isNull();

        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> oauth = ldapList.getBody().get(1);
        assertThat(oauth).isNotNull();
        assertThat(oauth.getConfig()).isNotNull();
        assertThat(oauth.getConfig()).isInstanceOf(AbstractExternalOAuthIdentityProviderDefinition.class);
        assertThat(oauth.getConfig().getRelyingPartySecret()).isNull();
    }

    @Test
    void retrieve_by_origin_providers_redacts_data() {
        when(mockIdentityProviderProvisioning.retrieveByOrigin(anyString(), anyString()))
                .thenReturn(getExternalOAuthProvider());
        ResponseEntity<List<IdentityProvider>> puppyList = identityProviderEndpoints.retrieveIdentityProviders("false", true, "puppy");
        assertThat(puppyList).isNotNull();
        assertThat(puppyList.getBody()).isNotNull();
        assertThat(puppyList.getBody()).hasSize(1);
        IdentityProvider<OIDCIdentityProviderDefinition> oidc = puppyList.getBody().getFirst();
        assertThat(oidc).isNotNull();
        assertThat(oidc.getConfig()).isNotNull();
        assertThat(oidc.getConfig()).isInstanceOf(AbstractExternalOAuthIdentityProviderDefinition.class);
        assertThat(oidc.getConfig().getRelyingPartySecret()).isNull();
        assertThat(oidc.getConfig().getAuthMethod()).isEqualTo(ClientAuthentication.CLIENT_SECRET_BASIC);
    }

    @Test
    void update_ldap_provider_patches_password() {
        IdentityProvider<LdapIdentityProviderDefinition> provider = retrieve_ldap_provider_by_id("id");
        provider.getConfig().setBindPassword(null);
        LdapIdentityProviderDefinition spy = Mockito.spy(provider.getConfig());
        provider.setConfig(spy);
        reset(mockIdentityProviderProvisioning);
        String zoneId = IdentityZone.getUaaZoneId();
        when(mockIdentityProviderProvisioning.retrieve(provider.getId(), zoneId)).thenReturn(getLdapDefinition());
        when(mockIdentityProviderProvisioning.update(any(), eq(zoneId))).thenReturn(getLdapDefinition());
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(provider.getId(), provider, true);
        verify(spy, times(1)).setBindPassword(getLdapDefinition().getConfig().getBindPassword());
        ArgumentCaptor<IdentityProvider> captor = ArgumentCaptor.forClass(IdentityProvider.class);
        verify(mockIdentityProviderProvisioning, times(1)).update(captor.capture(), eq(zoneId));
        assertThat(captor.getValue()).isNotNull();
        assertThat(captor.getAllValues()).hasSize(1);
        assertThat(((LdapIdentityProviderDefinition) captor.getValue().getConfig()).getBindPassword()).isEqualTo(getLdapDefinition().getConfig().getBindPassword());
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getConfig()).isNotNull();
        assertThat(response.getBody().getConfig()).isInstanceOf(LdapIdentityProviderDefinition.class);
        assertThat(((LdapIdentityProviderDefinition) response.getBody().getConfig()).getBindPassword()).isNull();
    }

    @Test
    void update_ldap_provider_takes_new_password() {
        IdentityProvider<LdapIdentityProviderDefinition> provider = retrieve_ldap_provider_by_id("id");
        LdapIdentityProviderDefinition spy = Mockito.spy(provider.getConfig());
        provider.setConfig(spy);
        spy.setBindPassword("newpassword");
        String zoneId = IdentityZone.getUaaZoneId();
        reset(mockIdentityProviderProvisioning);
        when(mockIdentityProviderProvisioning.retrieve(provider.getId(), zoneId)).thenReturn(getLdapDefinition());
        when(mockIdentityProviderProvisioning.update(any(), eq(zoneId))).thenReturn(getLdapDefinition());
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(provider.getId(), provider, true);
        verify(spy, times(1)).setBindPassword("newpassword");
        ArgumentCaptor<IdentityProvider> captor = ArgumentCaptor.forClass(IdentityProvider.class);
        verify(mockIdentityProviderProvisioning, times(1)).update(captor.capture(), eq(zoneId));
        assertThat(captor.getValue()).isNotNull();
        assertThat(captor.getAllValues()).hasSize(1);
        assertThat(((LdapIdentityProviderDefinition) captor.getValue().getConfig()).getBindPassword()).isEqualTo("newpassword");

        assertThat(response).isNotNull();
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getConfig()).isNotNull();
        assertThat(response.getBody().getConfig()).isInstanceOf(LdapIdentityProviderDefinition.class);
        assertThat(((LdapIdentityProviderDefinition) response.getBody().getConfig()).getBindPassword()).isNull();
    }

    @Test
    void update_saml_provider_validator_failed() {
        IdentityProvider provider = new IdentityProvider<>();
        String zoneId = IdentityZone.getUaaZoneId();
        provider.setId("id");
        provider.setType(SAML);
        provider.setIdentityZoneId(zoneId);
        provider.setOriginKey("originKey");
        SamlIdentityProviderDefinition samlConfig = new SamlIdentityProviderDefinition();
        provider.setConfig(samlConfig);
        doThrow(new IllegalArgumentException("error")).when(mockIdentityProviderConfigValidationDelegator).validate(any());
        when(mockIdentityProviderProvisioning.retrieve(any(), eq(zoneId))).thenReturn(provider);
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(provider.getId(), provider, true);
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
        verify(mockPlatformTransactionManager, never()).getTransaction(any());
        verify(mockIdpAliasHandler, never()).ensureConsistencyOfAliasEntity(any(), any());
    }

    @Test
    void update_saml_provider_alias_failed() {
        IdentityProvider provider = new IdentityProvider<>();
        String zoneId = IdentityZone.getUaaZoneId();
        provider.setId("id");
        provider.setType(SAML);
        provider.setIdentityZoneId(zoneId);
        provider.setOriginKey("originKey");
        SamlIdentityProviderDefinition samlConfig = new SamlIdentityProviderDefinition();
        provider.setConfig(samlConfig);
        when(mockIdentityProviderProvisioning.retrieve(any(), eq(zoneId))).thenReturn(provider);
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(provider.getId(), provider, true);
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
        verify(mockPlatformTransactionManager).getTransaction(any());
        verify(mockIdpAliasHandler, times(1)).ensureConsistencyOfAliasEntity(any(), any());
    }

    @Test
    void create_saml_provider_validator_failed() {
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        String zoneId = IdentityZone.getUaaZoneId();
        provider.setId("id");
        provider.setType(SAML);
        provider.setIdentityZoneId(zoneId);
        provider.setOriginKey("originKey");
        SamlIdentityProviderDefinition samlConfig = new SamlIdentityProviderDefinition();
        provider.setConfig(samlConfig);
        doThrow(new IllegalArgumentException("error")).when(mockIdentityProviderConfigValidationDelegator).validate(any());
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(provider, true);
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
        verify(mockIdpAliasHandler, never()).aliasPropertiesAreValid(provider, null);
    }

    @Test
    void create_saml_provider_alias_failed() {
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        String zoneId = IdentityZone.getUaaZoneId();
        provider.setId("id");
        provider.setType(SAML);
        provider.setIdentityZoneId(zoneId);
        provider.setOriginKey("originKey");
        SamlIdentityProviderDefinition samlConfig = new SamlIdentityProviderDefinition();
        provider.setConfig(samlConfig);
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(provider, true);
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
        verify(mockPlatformTransactionManager).getTransaction(any());
        verify(mockIdpAliasHandler, times(1)).ensureConsistencyOfAliasEntity(any(), any());
    }

    @Test
    void create_ldap_provider_removes_password() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProvider<LdapIdentityProviderDefinition> ldapDefinition = getLdapDefinition();
        assertThat(ldapDefinition.getConfig().getBindPassword()).isNotNull();
        when(mockIdentityProviderProvisioning.create(any(), eq(zoneId))).thenReturn(ldapDefinition);
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(ldapDefinition, true);
        IdentityProvider created = response.getBody();
        assertThat(created).isNotNull();
        assertThat(created.getType()).isEqualTo(LDAP);
        assertThat(created.getConfig()).isNotNull();
        assertThat(created.getConfig()).isInstanceOf(LdapIdentityProviderDefinition.class);
        assertThat(((LdapIdentityProviderDefinition) created.getConfig()).getBindPassword()).isNull();
    }

    @Nested
    class Alias {
        @BeforeEach
        void setUp() {
            arrangeAliasEntitiesEnabled(true);
        }

        @AfterEach
        void tearDown() {
            arrangeAliasEntitiesEnabled(false);
        }

        private final String customZoneId = UUID.randomUUID().toString();

        private void arrangeCurrentIdentityZone(final String zoneId) {
            when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);
        }

        private void arrangeAliasEntitiesEnabled(final boolean enabled) {
            ReflectionTestUtils.setField(identityProviderEndpoints, "aliasEntitiesEnabled", enabled);
        }

        @Nested
        class Create {
            @Test
            void shouldReturnOriginalIdpWithAliasId_WhenAliasPropertiesAreValid() {
                arrangeCurrentIdentityZone(UAA);

                final IdentityProvider<?> requestBody = getExternalOAuthProvider();
                requestBody.setId(null);
                requestBody.setIdentityZoneId(UAA);
                requestBody.setAliasId(null);
                requestBody.setAliasZid(customZoneId);

                // arrange validation returns true for request body
                when(mockIdpAliasHandler.aliasPropertiesAreValid(requestBody, null)).thenReturn(true);

                // idpProvisioning.create should return request body with new ID
                final IdentityProvider<?> createdOriginalIdp = shallowCloneIdp(requestBody);
                final String originalIdpId = UUID.randomUUID().toString();
                createdOriginalIdp.setId(originalIdpId);
                when(mockIdentityProviderProvisioning.create(requestBody, UAA)).thenReturn(createdOriginalIdp);

                // aliasHandler.ensureConsistency should add alias ID to original IdP
                final IdentityProvider originalIdpWithAliasId = shallowCloneIdp(createdOriginalIdp);
                final String aliasIdpId = UUID.randomUUID().toString();
                originalIdpWithAliasId.setAliasId(aliasIdpId);
                when(mockIdpAliasHandler.ensureConsistencyOfAliasEntity(createdOriginalIdp, null))
                        .thenReturn(originalIdpWithAliasId);

                final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(
                        requestBody,
                        true
                );

                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                assertThat(response.getBody()).isEqualTo(originalIdpWithAliasId);
            }

            @Test
            void shouldRespondWith422_WhenAliasPropertiesAreNotValid() {
                arrangeCurrentIdentityZone(UAA);

                final IdentityProvider<?> requestBody = getExternalOAuthProvider();
                requestBody.setId(null);
                requestBody.setIdentityZoneId(UAA);
                requestBody.setAliasId(null);
                requestBody.setAliasZid(customZoneId);

                // validation should fail for request body
                when(mockIdpAliasHandler.aliasPropertiesAreValid(requestBody, null)).thenReturn(false);

                final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(
                        requestBody,
                        true
                );

                assertThat(response.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
            }

            @ParameterizedTest
            @MethodSource
            void shouldRespondWithErrorCode_WhenExceptionIsThrownDuringAliasCreation(
                    final Exception thrownException,
                    final HttpStatus expectedStatusCode
            ) {
                arrangeCurrentIdentityZone(UAA);

                final IdentityProvider<?> requestBody = getExternalOAuthProvider();
                requestBody.setId(null);
                requestBody.setIdentityZoneId(UAA);
                requestBody.setAliasId(null);
                requestBody.setAliasZid(customZoneId);

                // arrange validation returns true for request body
                when(mockIdpAliasHandler.aliasPropertiesAreValid(requestBody, null)).thenReturn(true);

                // idpProvisioning.create should return request body with new ID
                final IdentityProvider<?> createdOriginalIdp = shallowCloneIdp(requestBody);
                final String originalIdpId = UUID.randomUUID().toString();
                createdOriginalIdp.setId(originalIdpId);
                when(mockIdentityProviderProvisioning.create(requestBody, UAA)).thenReturn(createdOriginalIdp);

                // aliasHandler.ensureConsistency should throw EntityAliasFailedException
                when(mockIdpAliasHandler.ensureConsistencyOfAliasEntity(createdOriginalIdp, null))
                        .thenThrow(thrownException);

                final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(
                        requestBody,
                        true
                );

                assertThat(response.getStatusCode()).isEqualTo(expectedStatusCode);
            }

            private static Stream<Arguments> shouldRespondWithErrorCode_WhenExceptionIsThrownDuringAliasCreation() {
                return Stream.of(
                        Arguments.of(new EntityAliasFailedException("Error", HttpStatus.BAD_REQUEST.value(), null), HttpStatus.BAD_REQUEST),
                        Arguments.of(new IllegalStateException(), HttpStatus.INTERNAL_SERVER_ERROR),
                        Arguments.of(new IdpAlreadyExistsException("IdP with this origin key already exists."), HttpStatus.CONFLICT)
                );
            }
        }

        @Nested
        class Update {
            @Test
            void shouldReturnOriginalIdpWithAliasId_WhenAliasPropertiesAreValid() {
                arrangeCurrentIdentityZone(UAA);

                final String originalIdpId = UUID.randomUUID().toString();
                final IdentityProvider<?> existingIdp = getExternalOAuthProvider();
                existingIdp.setId(originalIdpId);
                existingIdp.setIdentityZoneId(UAA);
                existingIdp.setAliasId(null);
                existingIdp.setAliasZid(null);
                when(mockIdentityProviderProvisioning.retrieve(originalIdpId, UAA)).thenReturn(existingIdp);

                final IdentityProvider<?> requestBody = shallowCloneIdp(existingIdp);
                requestBody.setAliasZid(customZoneId);

                // arrange validation returns true
                when(mockIdpAliasHandler.aliasPropertiesAreValid(requestBody, existingIdp))
                        .thenReturn(true);

                // idpProvisioning.update should return updated IdP
                final IdentityProvider<?> updatedOriginalIdp = shallowCloneIdp(requestBody);
                when(mockIdentityProviderProvisioning.update(requestBody, UAA)).thenReturn(updatedOriginalIdp);

                // aliasHandler.ensureConsistency should add alias ID to original IdP
                final IdentityProvider originalIdpWithAliasId = shallowCloneIdp(updatedOriginalIdp);
                final String aliasIdpId = UUID.randomUUID().toString();
                originalIdpWithAliasId.setAliasId(aliasIdpId);
                when(mockIdpAliasHandler.ensureConsistencyOfAliasEntity(
                        updatedOriginalIdp,
                        existingIdp
                )).thenReturn(originalIdpWithAliasId);

                final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(
                        originalIdpId,
                        requestBody,
                        true
                );

                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                assertThat(response.getBody()).isEqualTo(originalIdpWithAliasId);
            }

            @Test
            void shouldRespondWith422_WhenAliasPropertiesAreNotValid() {
                arrangeCurrentIdentityZone(UAA);

                final String originalIdpId = UUID.randomUUID().toString();
                final IdentityProvider<?> existingIdp = getExternalOAuthProvider();
                existingIdp.setId(originalIdpId);
                existingIdp.setIdentityZoneId(UAA);
                existingIdp.setAliasId(null);
                existingIdp.setAliasZid(null);
                when(mockIdentityProviderProvisioning.retrieve(originalIdpId, UAA)).thenReturn(existingIdp);

                final IdentityProvider<?> requestBody = shallowCloneIdp(existingIdp);
                requestBody.setAliasZid(customZoneId);

                // validation should fail for request body
                when(mockIdpAliasHandler.aliasPropertiesAreValid(requestBody, existingIdp))
                        .thenReturn(false);

                final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(
                        originalIdpId,
                        requestBody,
                        true
                );

                assertThat(response.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
            }

            @ParameterizedTest
            @MethodSource
            void shouldRespondWithErrorCode_WhenExceptionIsThrownDuringAliasCreation(
                    final Exception thrownException,
                    final HttpStatus expectedException
            ) {
                arrangeCurrentIdentityZone(UAA);

                final String originalIdpId = UUID.randomUUID().toString();
                final IdentityProvider<?> existingIdp = getExternalOAuthProvider();
                existingIdp.setId(originalIdpId);
                existingIdp.setIdentityZoneId(UAA);
                existingIdp.setAliasId(null);
                existingIdp.setAliasZid(null);
                when(mockIdentityProviderProvisioning.retrieve(originalIdpId, UAA)).thenReturn(existingIdp);

                final IdentityProvider<?> requestBody = shallowCloneIdp(existingIdp);
                requestBody.setAliasZid(customZoneId);

                // arrange validation returns true
                when(mockIdpAliasHandler.aliasPropertiesAreValid(requestBody, existingIdp))
                        .thenReturn(true);

                // idpProvisioning.update should return updated IdP
                final IdentityProvider<?> updatedOriginalIdp = shallowCloneIdp(requestBody);
                when(mockIdentityProviderProvisioning.update(requestBody, UAA)).thenReturn(updatedOriginalIdp);

                // aliasHandler.ensureConsistency should add alias ID to original IdP
                final IdentityProvider originalIdpWithAliasId = shallowCloneIdp(updatedOriginalIdp);
                final String aliasIdpId = UUID.randomUUID().toString();
                originalIdpWithAliasId.setAliasId(aliasIdpId);
                when(mockIdpAliasHandler.ensureConsistencyOfAliasEntity(
                        updatedOriginalIdp,
                        existingIdp
                )).thenThrow(thrownException);

                final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(
                        originalIdpId,
                        requestBody,
                        true
                );

                assertThat(response.getStatusCode()).isEqualTo(expectedException);
            }

            private static Stream<Arguments> shouldRespondWithErrorCode_WhenExceptionIsThrownDuringAliasCreation() {
                return Stream.of(
                        Arguments.of(new EntityAliasFailedException("Error", HttpStatus.BAD_REQUEST.value(), null), HttpStatus.BAD_REQUEST),
                        Arguments.of(new IllegalStateException(), HttpStatus.INTERNAL_SERVER_ERROR),
                        Arguments.of(new IdpAlreadyExistsException("IdP with this origin key already exists."), HttpStatus.CONFLICT)
                );
            }
        }

        @Nested
        class Delete {
            @Test
            void deleteIdpWithAlias() {
                final Pair<IdentityProvider<?>, IdentityProvider<?>> idpAndAlias = arrangeIdpWithAliasExists(UAA, customZoneId);
                final IdentityProvider<?> idp = idpAndAlias.getLeft();
                final IdentityProvider<?> aliasIdp = idpAndAlias.getRight();

                final ApplicationEventPublisher mockEventPublisher = mock(ApplicationEventPublisher.class);
                identityProviderEndpoints.setApplicationEventPublisher(mockEventPublisher);
                doNothing().when(mockEventPublisher).publishEvent(any());

                identityProviderEndpoints.deleteIdentityProvider(idp.getId(), true);
                final ArgumentCaptor<EntityDeletedEvent<?>> entityDeletedEventCaptor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
                verify(mockEventPublisher, times(2)).publishEvent(entityDeletedEventCaptor.capture());

                final EntityDeletedEvent<?> firstEvent = entityDeletedEventCaptor.getAllValues().getFirst();
                assertThat(firstEvent).isNotNull();
                assertThat(firstEvent.getIdentityZoneId()).isEqualTo(UAA);
                assertThat(((IdentityProvider<?>) firstEvent.getSource()).getId()).isEqualTo(idp.getId());

                final EntityDeletedEvent<?> secondEvent = entityDeletedEventCaptor.getAllValues().get(1);
                assertThat(secondEvent).isNotNull();
                assertThat(secondEvent.getIdentityZoneId()).isEqualTo(UAA);
                assertThat(((IdentityProvider<?>) secondEvent.getSource()).getId()).isEqualTo(aliasIdp.getId());
            }

            @Test
            void deleteIdpWithAliasDanglingReference() {
                final String idpId = UUID.randomUUID().toString();
                final String aliasIdpId = UUID.randomUUID().toString();

                final IdentityProvider<?> idp = new IdentityProvider<>();
                idp.setType(OIDC10);
                idp.setId(idpId);
                idp.setIdentityZoneId(UAA);
                idp.setAliasId(aliasIdpId);
                idp.setAliasZid(customZoneId);
                when(mockIdentityProviderProvisioning.retrieve(idpId, UAA)).thenReturn(idp);

                // alias IdP is not present -> dangling reference

                final ApplicationEventPublisher mockEventPublisher = mock(ApplicationEventPublisher.class);
                identityProviderEndpoints.setApplicationEventPublisher(mockEventPublisher);
                doNothing().when(mockEventPublisher).publishEvent(any());

                identityProviderEndpoints.deleteIdentityProvider(idpId, true);
                final ArgumentCaptor<EntityDeletedEvent<?>> entityDeletedEventCaptor = ArgumentCaptor.forClass(EntityDeletedEvent.class);

                // should only be called for the original IdP
                verify(mockEventPublisher, times(1)).publishEvent(entityDeletedEventCaptor.capture());

                final EntityDeletedEvent<?> firstEvent = entityDeletedEventCaptor.getAllValues().getFirst();
                assertThat(firstEvent).isNotNull();
                assertThat(firstEvent.getIdentityZoneId()).isEqualTo(UAA);
                assertThat(((IdentityProvider<?>) firstEvent.getSource()).getId()).isEqualTo(idpId);
            }

            @Test
            void deleteIdpWithAliasAliasFeatureDisabled() {
                arrangeAliasEntitiesEnabled(false);

                // ensure event publisher is present
                final ApplicationEventPublisher mockEventPublisher = mock(ApplicationEventPublisher.class);
                identityProviderEndpoints.setApplicationEventPublisher(mockEventPublisher);

                // arrange IdP with alias exists
                final Pair<IdentityProvider<?>, IdentityProvider<?>> idpAndAlias = arrangeIdpWithAliasExists(UAA, customZoneId);
                final IdentityProvider<?> idp = idpAndAlias.getLeft();

                final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.deleteIdentityProvider(
                        idp.getId(),
                        true
                );

                // deletion should be rejected
                assertThat(response.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
            }

            private Pair<IdentityProvider<?>, IdentityProvider<?>> arrangeIdpWithAliasExists(final String zone1Id, final String zone2Id) {
                assertThat(zone1Id).isNotBlank();
                assertThat(zone2Id).isNotBlank().isNotEqualTo(zone1Id);

                final String idpId = UUID.randomUUID().toString();
                final String aliasIdpId = UUID.randomUUID().toString();

                // arrange original IdP exists in zone 1
                final IdentityProvider<?> idp = new IdentityProvider<>();
                idp.setType(OIDC10);
                idp.setId(idpId);
                idp.setIdentityZoneId(zone1Id);
                idp.setAliasId(aliasIdpId);
                idp.setAliasZid(zone2Id);
                when(mockIdentityProviderProvisioning.retrieve(idpId, zone1Id)).thenReturn(idp);

                // arrange alias IdP exists in zone 2
                final IdentityProvider<?> aliasIdp = new IdentityProvider<>();
                aliasIdp.setType(OIDC10);
                aliasIdp.setId(aliasIdpId);
                aliasIdp.setIdentityZoneId(zone2Id);
                aliasIdp.setAliasId(idpId);
                aliasIdp.setAliasZid(zone1Id);
                lenient().when(mockIdpAliasHandler.retrieveAliasEntity(idp)).thenReturn(Optional.of(aliasIdp));

                return Pair.of(idp, aliasIdp);
            }
        }

        private static <T extends AbstractIdentityProviderDefinition> IdentityProvider<T> shallowCloneIdp(
                final IdentityProvider<T> idp
        ) {
            final IdentityProvider<T> cloneIdp = new IdentityProvider<>();
            cloneIdp.setId(idp.getId());
            cloneIdp.setName(idp.getName());
            cloneIdp.setOriginKey(idp.getOriginKey());
            cloneIdp.setConfig(idp.getConfig());
            cloneIdp.setType(idp.getType());
            cloneIdp.setCreated(idp.getCreated());
            cloneIdp.setLastModified(idp.getLastModified());
            cloneIdp.setIdentityZoneId(idp.getIdentityZoneId());
            cloneIdp.setAliasId(idp.getAliasId());
            cloneIdp.setAliasZid(idp.getAliasZid());
            cloneIdp.setActive(idp.isActive());
            assertThat(cloneIdp).isEqualTo(idp);
            return cloneIdp;
        }
    }

    @Test
    void create_oauth_provider_removes_password() {
        String zoneId = IdentityZone.getUaaZoneId();
        for (String type : Arrays.asList(OIDC10, OAUTH20)) {
            IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> externalOAuthDefinition = getExternalOAuthProvider();
            assertThat(externalOAuthDefinition.getConfig().getRelyingPartySecret()).isNotNull();
            externalOAuthDefinition.setType(type);
            when(mockIdentityProviderProvisioning.create(any(), eq(zoneId))).thenReturn(externalOAuthDefinition);
            ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(externalOAuthDefinition, true);
            IdentityProvider created = response.getBody();
            assertThat(created).isNotNull();
            assertThat(created.getType()).isEqualTo(type);
            assertThat(created.getConfig()).isNotNull();
            assertThat(created.getConfig()).isInstanceOf(AbstractExternalOAuthIdentityProviderDefinition.class);
            assertThat(((AbstractExternalOAuthIdentityProviderDefinition) created.getConfig()).getRelyingPartySecret()).isNull();
            assertThat(((AbstractExternalOAuthIdentityProviderDefinition) created.getConfig()).getAuthMethod()).isEqualTo(ClientAuthentication.CLIENT_SECRET_BASIC);
        }
    }

    @Test
    void create_oauth_provider_set_auth_method_none() {
        String zoneId = IdentityZone.getUaaZoneId();
        for (String type : Arrays.asList(OIDC10, OAUTH20)) {
            IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> externalOAuthDefinition = getExternalOAuthProvider();
            assertThat(externalOAuthDefinition.getConfig().getRelyingPartySecret()).isNotNull();
            externalOAuthDefinition.setType(type);
            when(mockIdentityProviderProvisioning.create(any(), eq(zoneId))).thenReturn(externalOAuthDefinition);
            ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(externalOAuthDefinition, true);
            IdentityProvider created = response.getBody();
            assertThat(created).isNotNull();
            assertThat(created.getType()).isEqualTo(type);
            assertThat(created.getConfig()).isNotNull();
            assertThat(created.getConfig()).isInstanceOf(AbstractExternalOAuthIdentityProviderDefinition.class);
            assertThat(((AbstractExternalOAuthIdentityProviderDefinition) created.getConfig()).getRelyingPartySecret()).isNull();
            assertThat(((AbstractExternalOAuthIdentityProviderDefinition) created.getConfig()).getAuthMethod()).isEqualTo(ClientAuthentication.CLIENT_SECRET_BASIC);
            externalOAuthDefinition.getConfig().setRelyingPartySecret(null);
            externalOAuthDefinition.getConfig().setAuthMethod("none");
            AbstractExternalOAuthIdentityProviderDefinition spy = Mockito.spy(externalOAuthDefinition.getConfig());
            when(mockIdentityProviderProvisioning.retrieve(eq(externalOAuthDefinition.getId()), eq(zoneId))).thenReturn(getExternalOAuthProvider());
            response = identityProviderEndpoints.updateIdentityProvider(created.getId(), externalOAuthDefinition, true);
            IdentityProvider upated = response.getBody();
            assertThat(upated).isNotNull();
            assertThat(upated.getType()).isEqualTo(type);
            assertThat(upated.getConfig()).isNotNull();
            verify(spy, never()).setRelyingPartySecret(eq(getExternalOAuthProvider().getConfig().getRelyingPartySecret()));
            assertThat(((AbstractExternalOAuthIdentityProviderDefinition) upated.getConfig()).getAuthMethod()).isEqualTo(ClientAuthentication.NONE);
        }
    }

    @Test
    void patchIdentityProviderStatusInvalidPayload() {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertThat(responseEntity.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
    }

    @Test
    void patchIdentityProviderStatusInvalidIDP() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider notUAAIDP = new IdentityProvider<>();
        notUAAIDP.setType("NOT_UAA");
        notUAAIDP.setConfig(new SamlIdentityProviderDefinition());
        when(mockIdentityProviderProvisioning.retrieve(anyString(), eq(zoneId))).thenReturn(notUAAIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertThat(responseEntity.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
    }

    @Test
    void patchIdentityProviderStatusWithNoIDPDefinition() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider invalidIDP = new IdentityProvider<>();
        invalidIDP.setConfig(null);
        invalidIDP.setType(OriginKeys.UAA);
        when(mockIdentityProviderProvisioning.retrieve(anyString(), eq(zoneId))).thenReturn(invalidIDP);
        ResponseEntity<IdentityProviderStatus> responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertThat(responseEntity.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
    }

    @Test
    void patchIdentityProviderStatusWithNoPasswordPolicy() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider invalidIDP = new IdentityProvider<>();
        invalidIDP.setType(OriginKeys.UAA);
        invalidIDP.setConfig(new UaaIdentityProviderDefinition(null, null));
        when(mockIdentityProviderProvisioning.retrieve(anyString(), eq(zoneId))).thenReturn(invalidIDP);
        ResponseEntity<IdentityProviderStatus> responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertThat(responseEntity.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
    }

    @Test
    void patchIdentityProviderStatus() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider validIDP = new IdentityProvider<>();
        validIDP.setType(OriginKeys.UAA);
        validIDP.setConfig(new UaaIdentityProviderDefinition(new PasswordPolicy(), null));
        when(mockIdentityProviderProvisioning.retrieve(anyString(), eq(zoneId))).thenReturn(validIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void deleteIdentityProviderExisting() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProvider validIDP = new IdentityProvider<>();
        validIDP.setType(OriginKeys.UAA);
        validIDP.setConfig(new UaaIdentityProviderDefinition(
                new PasswordPolicy(), null));
        String identityProviderIdentifier = UUID.randomUUID().toString();
        when(mockIdentityProviderProvisioning.retrieve(
                identityProviderIdentifier, zoneId)).thenReturn(validIDP);
        identityProviderEndpoints.setApplicationEventPublisher(
                mock(ApplicationEventPublisher.class));

        // Verify that delete succeeds
        ResponseEntity<IdentityProvider> deleteResponse =
                identityProviderEndpoints.deleteIdentityProvider(
                        identityProviderIdentifier, false);
        assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(deleteResponse.getBody()).isEqualTo(validIDP);
    }

    @Test
    void deleteIdentityProviderNotExisting() {
        String zoneId = IdentityZone.getUaaZoneId();
        String identityProviderIdentifier = UUID.randomUUID().toString();
        when(mockIdentityProviderProvisioning.retrieve(
                identityProviderIdentifier, zoneId)).thenReturn(null);

        ResponseEntity<IdentityProvider> deleteResponse =
                identityProviderEndpoints.deleteIdentityProvider(
                        identityProviderIdentifier, false);
        assertThat(deleteResponse.getStatusCode()).isEqualTo(UNPROCESSABLE_ENTITY);
    }

    @Test
    void deleteIdentityProviderResponseNotContainingRelyingPartySecret() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProvider validIDP = new IdentityProvider<>();
        validIDP.setType(OIDC10);
        OIDCIdentityProviderDefinition identityProviderDefinition =
                new OIDCIdentityProviderDefinition();
        identityProviderDefinition.setRelyingPartySecret("myRelyingPartySecret");
        validIDP.setConfig(identityProviderDefinition);
        String identityProviderIdentifier = UUID.randomUUID().toString();
        when(mockIdentityProviderProvisioning.retrieve(
                identityProviderIdentifier, zoneId)).thenReturn(validIDP);
        identityProviderEndpoints.setApplicationEventPublisher(
                mock(ApplicationEventPublisher.class));

        // Verify that the response's config does not contain relyingPartySecret
        ResponseEntity<IdentityProvider> deleteResponse =
                identityProviderEndpoints.deleteIdentityProvider(
                        identityProviderIdentifier, false);
        assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(((AbstractExternalOAuthIdentityProviderDefinition) deleteResponse
                .getBody().getConfig()).getRelyingPartySecret()).isNull();
    }

    @Test
    void deleteIdentityProviderResponseNotContainingBindPassword() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProvider identityProvider = getLdapDefinition();
        when(mockIdentityProviderProvisioning.retrieve(
                identityProvider.getId(), zoneId)).thenReturn(identityProvider);
        identityProviderEndpoints.setApplicationEventPublisher(
                mock(ApplicationEventPublisher.class));

        // Verify that the response's config does not contain bindPassword
        ResponseEntity<IdentityProvider> deleteResponse =
                identityProviderEndpoints.deleteIdentityProvider(
                        identityProvider.getId(), false);
        assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(((LdapIdentityProviderDefinition) deleteResponse
                .getBody().getConfig()).getBindPassword()).isNull();
    }

    @Test
    void set_auth_client_secret() {
        for (String type : Arrays.asList(OIDC10, OAUTH20)) {
            IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> provider = getExternalOAuthProvider();
            AbstractExternalOAuthIdentityProviderDefinition def = provider.getConfig();
            AbstractExternalOAuthIdentityProviderDefinition spy = Mockito.spy(def);
            provider.setConfig(spy);
            provider.setType(type);
            // standard secret usage
            when(spy.getRelyingPartySecret()).thenReturn("secret");
            identityProviderEndpoints.setAuthMethod(provider);
            assertThat(provider.getConfig().getAuthMethod()).isEqualTo(ClientAuthentication.CLIENT_SECRET_BASIC);
            // use secrets in body
            when(spy.isClientAuthInBody()).thenReturn(true);
            identityProviderEndpoints.setAuthMethod(provider);
            assertThat(provider.getConfig().getAuthMethod()).isEqualTo(ClientAuthentication.CLIENT_SECRET_POST);
            // no secret usage but treat it as public client
            when(spy.getRelyingPartySecret()).thenReturn(null);
            identityProviderEndpoints.setAuthMethod(provider);
            assertThat(provider.getConfig().getAuthMethod()).isEqualTo(ClientAuthentication.NONE);
            // private_key_jwt in OIDC case
            if (OIDC10.equals(type)) {
                OIDCIdentityProviderDefinition oidcSpy = (OIDCIdentityProviderDefinition) spy;
                when(oidcSpy.getJwtClientAuthentication()).thenReturn(Boolean.TRUE);
                identityProviderEndpoints.setAuthMethod(provider);
                assertThat(provider.getConfig().getAuthMethod()).isEqualTo(ClientAuthentication.PRIVATE_KEY_JWT);
            }
        }
    }
}
