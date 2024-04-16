package org.cloudfoundry.identity.uaa.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UNKNOWN;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

import org.apache.commons.lang3.tuple.Pair;
import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;

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
    private IdentityZoneProvisioning mockIdentityZoneProvisioning;

    @Mock
    private IdentityProviderAliasHandler mockIdpAliasHandler;

    @InjectMocks
    private IdentityProviderEndpoints identityProviderEndpoints;

    @BeforeEach
    void setup() {
        lenient().when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        arrangeAliasEntitiesEnabled(true);

        lenient().when(mockIdpAliasHandler.aliasPropertiesAreValid(any(), any()))
                .thenReturn(true);
        lenient().when(mockIdpAliasHandler.ensureConsistencyOfAliasEntity(any(), any()))
                .then(invocationOnMock -> invocationOnMock.getArgument(0));
    }

    IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> getExternalOAuthProvider() {
        IdentityProvider identityProvider = new IdentityProvider<>();
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
    void retrieve_oauth_provider_by_id_redacts_password() throws Exception {
        retrieve_oauth_provider_by_id("", OriginKeys.OAUTH20);
        retrieve_oauth_provider_by_id("", OriginKeys.OIDC10);
    }

    IdentityProvider<LdapIdentityProviderDefinition> retrieve_oauth_provider_by_id(String id, String type) {
        IdentityProvider provider = getExternalOAuthProvider();
        provider.setType(type);
        when(mockIdentityProviderProvisioning.retrieve(anyString(), anyString())).thenReturn(provider);
        ResponseEntity<IdentityProvider> oauth = identityProviderEndpoints.retrieveIdentityProvider(id, true);
        assertNotNull(oauth);
        assertEquals(200, oauth.getStatusCode().value());
        assertNotNull(oauth.getBody());
        assertNotNull(oauth.getBody().getConfig());
        assertTrue(oauth.getBody().getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition);
        assertNull(((AbstractExternalOAuthIdentityProviderDefinition) oauth.getBody().getConfig()).getRelyingPartySecret());
        return oauth.getBody();
    }

    @Test
    void retrieve_ldap_provider_by_id_redacts_password() throws Exception {
        retrieve_ldap_provider_by_id("");
    }

    IdentityProvider<LdapIdentityProviderDefinition> retrieve_ldap_provider_by_id(String id) {
        when(mockIdentityProviderProvisioning.retrieve(anyString(), anyString())).thenReturn(getLdapDefinition());
        ResponseEntity<IdentityProvider> ldap = identityProviderEndpoints.retrieveIdentityProvider(id, true);
        assertNotNull(ldap);
        assertEquals(200, ldap.getStatusCode().value());
        assertNotNull(ldap.getBody());
        assertNotNull(ldap.getBody().getConfig());
        assertTrue(ldap.getBody().getConfig() instanceof LdapIdentityProviderDefinition);
        assertNull(((LdapIdentityProviderDefinition) ldap.getBody().getConfig()).getBindPassword());
        return ldap.getBody();
    }

    @Test
    void remove_bind_password() {
        remove_sensitive_data(() -> getLdapDefinition(),
                LDAP,
                (spy) -> verify((LdapIdentityProviderDefinition) spy, times(1)).setBindPassword(isNull()));
    }

    @Test
    void remove_client_secret() {
        for (String type : Arrays.asList(OIDC10, OAUTH20)) {
            remove_sensitive_data(() -> getExternalOAuthProvider(),
                    type,
                    (spy) -> verify((AbstractExternalOAuthIdentityProviderDefinition) spy, times(1)).setRelyingPartySecret(isNull()));
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
        IdentityProvider provider = getExternalOAuthProvider();
        AbstractExternalOAuthIdentityProviderDefinition spy = Mockito.spy((AbstractExternalOAuthIdentityProviderDefinition) provider.getConfig());
        provider.setConfig(spy);
        provider.setType(UNKNOWN);
        identityProviderEndpoints.redactSensitiveData(provider);
        verify(spy, never()).setRelyingPartySecret(isNull());
    }

    @Test
    void remove_bind_password_non_ldap() {
        IdentityProvider provider = getLdapDefinition();
        LdapIdentityProviderDefinition spy = Mockito.spy((LdapIdentityProviderDefinition) provider.getConfig());
        provider.setConfig(spy);
        provider.setType(OriginKeys.UNKNOWN);
        identityProviderEndpoints.redactSensitiveData(provider);
        verify(spy, never()).setBindPassword(isNull());
    }

    @Test
    void patch_bind_password() {
        IdentityProvider provider = getLdapDefinition();
        LdapIdentityProviderDefinition def = (LdapIdentityProviderDefinition) provider.getConfig();
        def.setBindPassword(null);
        LdapIdentityProviderDefinition spy = Mockito.spy(def);
        provider.setConfig(spy);
        reset(mockIdentityProviderProvisioning);
        String zoneId = IdentityZone.getUaaZoneId();
        when(mockIdentityProviderProvisioning.retrieve(eq(provider.getId()), eq(zoneId))).thenReturn(getLdapDefinition());
        identityProviderEndpoints.patchSensitiveData(provider.getId(), provider);
        verify(spy, times(1)).setBindPassword(eq(getLdapDefinition().getConfig().getBindPassword()));
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
            when(mockIdentityProviderProvisioning.retrieve(eq(provider.getId()), eq(zoneId))).thenReturn(getExternalOAuthProvider());
            identityProviderEndpoints.patchSensitiveData(provider.getId(), provider);
            verify(spy, times(1)).setRelyingPartySecret(eq(getExternalOAuthProvider().getConfig().getRelyingPartySecret()));
        }
    }

    @Test
    void patch_bind_password_non_ldap() {
        IdentityProvider provider = getLdapDefinition();
        LdapIdentityProviderDefinition spy = Mockito.spy((LdapIdentityProviderDefinition) provider.getConfig());
        provider.setConfig(spy);
        provider.setType(OriginKeys.UNKNOWN);
        identityProviderEndpoints.redactSensitiveData(provider);
        verify(spy, never()).setBindPassword(any());
    }

    @Test
    void retrieve_all_providers_redacts_data() {
        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), anyString()))
                .thenReturn(Arrays.asList(getLdapDefinition(), getExternalOAuthProvider()));
        ResponseEntity<List<IdentityProvider>> ldapList = identityProviderEndpoints.retrieveIdentityProviders("false", true);
        assertNotNull(ldapList);
        assertNotNull(ldapList.getBody());
        assertEquals(2, ldapList.getBody().size());
        IdentityProvider<LdapIdentityProviderDefinition> ldap = ldapList.getBody().get(0);
        assertNotNull(ldap);
        assertNotNull(ldap.getConfig());
        assertTrue(ldap.getConfig() instanceof LdapIdentityProviderDefinition);
        assertNull(ldap.getConfig().getBindPassword());

        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> oauth = ldapList.getBody().get(1);
        assertNotNull(oauth);
        assertNotNull(oauth.getConfig());
        assertTrue(oauth.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition);
        assertNull(oauth.getConfig().getRelyingPartySecret());
    }

    @Test
    void update_ldap_provider_patches_password() throws Exception {
        IdentityProvider<LdapIdentityProviderDefinition> provider = retrieve_ldap_provider_by_id("id");
        provider.getConfig().setBindPassword(null);
        LdapIdentityProviderDefinition spy = Mockito.spy(provider.getConfig());
        provider.setConfig(spy);
        reset(mockIdentityProviderProvisioning);
        String zoneId = IdentityZone.getUaaZoneId();
        when(mockIdentityProviderProvisioning.retrieve(eq(provider.getId()), eq(zoneId))).thenReturn(getLdapDefinition());
        when(mockIdentityProviderProvisioning.update(any(), eq(zoneId))).thenReturn(getLdapDefinition());
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(provider.getId(), provider, true);
        verify(spy, times(1)).setBindPassword(eq(getLdapDefinition().getConfig().getBindPassword()));
        ArgumentCaptor<IdentityProvider> captor = ArgumentCaptor.forClass(IdentityProvider.class);
        verify(mockIdentityProviderProvisioning, times(1)).update(captor.capture(), eq(zoneId));
        assertNotNull(captor.getValue());
        assertEquals(1, captor.getAllValues().size());
        assertEquals(getLdapDefinition().getConfig().getBindPassword(), ((LdapIdentityProviderDefinition) captor.getValue().getConfig()).getBindPassword());
        assertNotNull(response);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().getConfig());
        assertTrue(response.getBody().getConfig() instanceof LdapIdentityProviderDefinition);
        assertNull(((LdapIdentityProviderDefinition) response.getBody().getConfig()).getBindPassword());
    }

    @Test
    void update_ldap_provider_takes_new_password() throws Exception {
        IdentityProvider<LdapIdentityProviderDefinition> provider = retrieve_ldap_provider_by_id("id");
        LdapIdentityProviderDefinition spy = Mockito.spy(provider.getConfig());
        provider.setConfig(spy);
        spy.setBindPassword("newpassword");
        String zoneId = IdentityZone.getUaaZoneId();
        reset(mockIdentityProviderProvisioning);
        when(mockIdentityProviderProvisioning.retrieve(eq(provider.getId()), eq(zoneId))).thenReturn(getLdapDefinition());
        when(mockIdentityProviderProvisioning.update(any(), eq(zoneId))).thenReturn(getLdapDefinition());
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(provider.getId(), provider, true);
        verify(spy, times(1)).setBindPassword(eq("newpassword"));
        ArgumentCaptor<IdentityProvider> captor = ArgumentCaptor.forClass(IdentityProvider.class);
        verify(mockIdentityProviderProvisioning, times(1)).update(captor.capture(), eq(zoneId));
        assertNotNull(captor.getValue());
        assertEquals(1, captor.getAllValues().size());
        assertEquals("newpassword", ((LdapIdentityProviderDefinition) captor.getValue().getConfig()).getBindPassword());

        assertNotNull(response);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().getConfig());
        assertTrue(response.getBody().getConfig() instanceof LdapIdentityProviderDefinition);
        assertNull(((LdapIdentityProviderDefinition) response.getBody().getConfig()).getBindPassword());
    }

    @Test
    void create_ldap_provider_removes_password() throws Exception {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProvider<LdapIdentityProviderDefinition> ldapDefinition = getLdapDefinition();
        assertNotNull(ldapDefinition.getConfig().getBindPassword());
        when(mockIdentityProviderProvisioning.create(any(), eq(zoneId))).thenReturn(ldapDefinition);
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(ldapDefinition, true);
        IdentityProvider created = response.getBody();
        assertNotNull(created);
        assertEquals(LDAP, created.getType());
        assertNotNull(created.getConfig());
        assertTrue(created.getConfig() instanceof LdapIdentityProviderDefinition);
        assertNull(((LdapIdentityProviderDefinition) created.getConfig()).getBindPassword());
    }

    @Nested
    class Alias {
        private final String customZoneId = UUID.randomUUID().toString();

        private void arrangeCurrentIdentityZone(final String zoneId) {
            when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);
        }

        @Nested
        class Create {
            @Test
            void shouldReturnOriginalIdpWithAliasId_WhenAliasPropertiesAreValid() /* throws MetadataProviderException */ {
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

                Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                Assertions.assertThat(response.getBody()).isEqualTo(originalIdpWithAliasId);
            }

            @Test
            void shouldRespondWith422_WhenAliasPropertiesAreNotValid() /* throws MetadataProviderException */ {
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

                Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
            }

            @ParameterizedTest
            @MethodSource
            void shouldRespondWithErrorCode_WhenExceptionIsThrownDuringAliasCreation(
                    final Exception thrownException,
                    final HttpStatus expectedStatusCode
            ) /* throws MetadataProviderException */ {
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

                Assertions.assertThat(response.getStatusCode()).isEqualTo(expectedStatusCode);
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
            void shouldReturnOriginalIdpWithAliasId_WhenAliasPropertiesAreValid() /* throws MetadataProviderException */ {
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

                Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                Assertions.assertThat(response.getBody()).isEqualTo(originalIdpWithAliasId);
            }

            @Test
            void shouldRespondWith422_WhenAliasPropertiesAreNotValid() /* throws MetadataProviderException */ {
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

                Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
            }

            @ParameterizedTest
            @MethodSource
            void shouldRespondWithErrorCode_WhenExceptionIsThrownDuringAliasCreation(
                    final Exception thrownException,
                    final HttpStatus expectedException
            ) /* throws MetadataProviderException */ {
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

                Assertions.assertThat(response.getStatusCode()).isEqualTo(expectedException);
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
            void testDeleteIdpWithAlias() {
                final Pair<IdentityProvider<?>, IdentityProvider<?>> idpAndAlias = arrangeIdpWithAliasExists(UAA, customZoneId);
                final IdentityProvider<?> idp = idpAndAlias.getLeft();
                final IdentityProvider<?> aliasIdp = idpAndAlias.getRight();

                final ApplicationEventPublisher mockEventPublisher = mock(ApplicationEventPublisher.class);
                identityProviderEndpoints.setApplicationEventPublisher(mockEventPublisher);
                doNothing().when(mockEventPublisher).publishEvent(any());

                identityProviderEndpoints.deleteIdentityProvider(idp.getId(), true);
                final ArgumentCaptor<EntityDeletedEvent<?>> entityDeletedEventCaptor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
                verify(mockEventPublisher, times(2)).publishEvent(entityDeletedEventCaptor.capture());

                final EntityDeletedEvent<?> firstEvent = entityDeletedEventCaptor.getAllValues().get(0);
                Assertions.assertThat(firstEvent).isNotNull();
                Assertions.assertThat(firstEvent.getIdentityZoneId()).isEqualTo(UAA);
                Assertions.assertThat(((IdentityProvider<?>) firstEvent.getSource()).getId()).isEqualTo(idp.getId());

                final EntityDeletedEvent<?> secondEvent = entityDeletedEventCaptor.getAllValues().get(1);
                Assertions.assertThat(secondEvent).isNotNull();
                Assertions.assertThat(secondEvent.getIdentityZoneId()).isEqualTo(UAA);
                Assertions.assertThat(((IdentityProvider<?>) secondEvent.getSource()).getId()).isEqualTo(aliasIdp.getId());
            }

            @Test
            void testDeleteIdpWithAlias_DanglingReference() {
                final String idpId = UUID.randomUUID().toString();
                final String aliasIdpId = UUID.randomUUID().toString();
                final String customZoneId = UUID.randomUUID().toString();

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

                final EntityDeletedEvent<?> firstEvent = entityDeletedEventCaptor.getAllValues().get(0);
                Assertions.assertThat(firstEvent).isNotNull();
                Assertions.assertThat(firstEvent.getIdentityZoneId()).isEqualTo(UAA);
                Assertions.assertThat(((IdentityProvider<?>) firstEvent.getSource()).getId()).isEqualTo(idpId);
            }

            @Test
            void testDeleteIdpWithAlias_AliasFeatureDisabled() {
                arrangeAliasEntitiesEnabled(false);

                // ensure event publisher is present
                final ApplicationEventPublisher mockEventPublisher = mock(ApplicationEventPublisher.class);
                identityProviderEndpoints.setApplicationEventPublisher(mockEventPublisher);

                // arrange IdP with alias exists
                final String customZoneId = UUID.randomUUID().toString();
                final Pair<IdentityProvider<?>, IdentityProvider<?>> idpAndAlias = arrangeIdpWithAliasExists(UAA, customZoneId);
                final IdentityProvider<?> idp = idpAndAlias.getLeft();

                final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.deleteIdentityProvider(
                        idp.getId(),
                        true
                );

                // deletion should be rejected
                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
            }

            private Pair<IdentityProvider<?>, IdentityProvider<?>> arrangeIdpWithAliasExists(final String zone1Id, final String zone2Id) {
                Assertions.assertThat(zone1Id).isNotBlank();
                Assertions.assertThat(zone2Id).isNotBlank().isNotEqualTo(zone1Id);

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
    void create_oauth_provider_removes_password() throws Exception {
        String zoneId = IdentityZone.getUaaZoneId();
        for (String type : Arrays.asList(OIDC10, OAUTH20)) {
            IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> externalOAuthDefinition = getExternalOAuthProvider();
            assertNotNull(externalOAuthDefinition.getConfig().getRelyingPartySecret());
            externalOAuthDefinition.setType(type);
            when(mockIdentityProviderProvisioning.create(any(), eq(zoneId))).thenReturn(externalOAuthDefinition);
            ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(externalOAuthDefinition, true);
            IdentityProvider created = response.getBody();
            assertNotNull(created);
            assertEquals(type, created.getType());
            assertNotNull(created.getConfig());
            assertTrue(created.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition);
            assertNull(((AbstractExternalOAuthIdentityProviderDefinition) created.getConfig()).getRelyingPartySecret());
        }
    }

    @Test
    void testPatchIdentityProviderStatusInvalidPayload() {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntity.getStatusCode());
    }

    @Test
    void testPatchIdentityProviderStatusInvalidIDP() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider notUAAIDP = new IdentityProvider();
        notUAAIDP.setType("NOT_UAA");
        notUAAIDP.setConfig(new SamlIdentityProviderDefinition());
        when(mockIdentityProviderProvisioning.retrieve(anyString(), eq(zoneId))).thenReturn(notUAAIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntity.getStatusCode());
    }

    @Test
    void testPatchIdentityProviderStatusWithNoIDPDefinition() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider invalidIDP = new IdentityProvider();
        invalidIDP.setConfig(null);
        invalidIDP.setType(OriginKeys.UAA);
        when(mockIdentityProviderProvisioning.retrieve(anyString(), eq(zoneId))).thenReturn(invalidIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntity.getStatusCode());
    }

    @Test
    void testPatchIdentityProviderStatusWithNoPasswordPolicy() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider invalidIDP = new IdentityProvider();
        invalidIDP.setType(OriginKeys.UAA);
        invalidIDP.setConfig(new UaaIdentityProviderDefinition(null, null));
        when(mockIdentityProviderProvisioning.retrieve(anyString(), eq(zoneId))).thenReturn(invalidIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntity.getStatusCode());
    }

    @Test
    void testPatchIdentityProviderStatus() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider validIDP = new IdentityProvider();
        validIDP.setType(OriginKeys.UAA);
        validIDP.setConfig(new UaaIdentityProviderDefinition(new PasswordPolicy(), null));
        when(mockIdentityProviderProvisioning.retrieve(anyString(), eq(zoneId))).thenReturn(validIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }

    @Test
    void testDeleteIdentityProviderExisting() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProvider validIDP = new IdentityProvider();
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
        assertEquals(HttpStatus.OK, deleteResponse.getStatusCode());
        assertEquals(validIDP, deleteResponse.getBody());
    }

    @Test
    void testDeleteIdentityProviderNotExisting() {
        String zoneId = IdentityZone.getUaaZoneId();
        String identityProviderIdentifier = UUID.randomUUID().toString();
        when(mockIdentityProviderProvisioning.retrieve(
                identityProviderIdentifier, zoneId)).thenReturn(null);

        ResponseEntity<IdentityProvider> deleteResponse =
                identityProviderEndpoints.deleteIdentityProvider(
                        identityProviderIdentifier, false);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY,
                deleteResponse.getStatusCode());
    }

    @Test
    void testDeleteIdentityProviderResponseNotContainingRelyingPartySecret() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProvider validIDP = new IdentityProvider();
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
        assertEquals(HttpStatus.OK, deleteResponse.getStatusCode());
        assertNull(((AbstractExternalOAuthIdentityProviderDefinition)deleteResponse
                .getBody().getConfig()).getRelyingPartySecret());
    }

    @Test
    void testDeleteIdentityProviderResponseNotContainingBindPassword() {
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
        assertEquals(HttpStatus.OK, deleteResponse.getStatusCode());
        assertNull(((LdapIdentityProviderDefinition)deleteResponse
                .getBody().getConfig()).getBindPassword());
    }

    private void arrangeAliasEntitiesEnabled(final boolean enabled) {
        ReflectionTestUtils.setField(identityProviderEndpoints, "aliasEntitiesEnabled", enabled);
    }
}
