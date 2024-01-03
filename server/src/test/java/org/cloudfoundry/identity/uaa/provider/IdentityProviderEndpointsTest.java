package org.cloudfoundry.identity.uaa.provider;

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
import static org.mockito.ArgumentMatchers.argThat;
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
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatcher;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.PlatformTransactionManager;

import com.sun.mail.imap.protocol.ID;

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

    @InjectMocks
    private IdentityProviderEndpoints identityProviderEndpoints;

    @BeforeEach
    void setup() {
        lenient().when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
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
    void testUpdateIdentityProvider_AlreadyMirrored_InvalidAliasPropertyChange() throws MetadataProviderException {
        final String existingIdpId = UUID.randomUUID().toString();
        final String customZoneId = UUID.randomUUID().toString();
        final String mirroredIdpId = UUID.randomUUID().toString();

        final Supplier<IdentityProvider<?>> existingIdpSupplier = () -> {
            final IdentityProvider<?> idp = getExternalOAuthProvider();
            idp.setId(existingIdpId);
            idp.setAliasZid(customZoneId);
            idp.setAliasId(mirroredIdpId);
            return idp;
        };

        // original IdP with reference to a mirrored IdP
        final IdentityProvider<?> existingIdp = existingIdpSupplier.get();
        when(mockIdentityProviderProvisioning.retrieve(existingIdpId, IdentityZone.getUaaZoneId()))
                .thenReturn(existingIdp);

        // (1) aliasId removed
        IdentityProvider<?> requestBody = existingIdpSupplier.get();
        requestBody.setAliasId("");
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(existingIdpId, requestBody, true);
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);

        // (2) aliasId changed
        requestBody = existingIdpSupplier.get();
        requestBody.setAliasId(UUID.randomUUID().toString());
        response = identityProviderEndpoints.updateIdentityProvider(existingIdpId, requestBody, true);
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);

        // (3) aliasZid removed
        requestBody = existingIdpSupplier.get();
        requestBody.setAliasZid("");
        response = identityProviderEndpoints.updateIdentityProvider(existingIdpId, requestBody, true);
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);

        // (4) aliasZid changed
        requestBody = existingIdpSupplier.get();
        requestBody.setAliasZid(UUID.randomUUID().toString());
        response = identityProviderEndpoints.updateIdentityProvider(existingIdpId, requestBody, true);
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @Test
    void testUpdateIdentityProvider_AlreadyMirrored_ValidChange() throws MetadataProviderException {
        final String existingIdpId = UUID.randomUUID().toString();
        final String customZoneId = UUID.randomUUID().toString();
        final String mirroredIdpId = UUID.randomUUID().toString();

        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(UAA);

        final Supplier<IdentityProvider<?>> existingIdpSupplier = () -> {
            final IdentityProvider<?> idp = getExternalOAuthProvider();
            idp.setId(existingIdpId);
            idp.setAliasZid(customZoneId);
            idp.setAliasId(mirroredIdpId);
            return idp;
        };

        final IdentityProvider<?> existingIdp = existingIdpSupplier.get();
        when(mockIdentityProviderProvisioning.retrieve(existingIdpId, UAA)).thenReturn(existingIdp);
        final IdentityProvider<?> mirroredIdp = getExternalOAuthProvider();
        mirroredIdp.setId(mirroredIdpId);
        mirroredIdp.setIdentityZoneId(customZoneId);
        mirroredIdp.setAliasId(existingIdp.getId());
        mirroredIdp.setAliasZid(UAA);
        when(mockIdentityProviderProvisioning.retrieve(mirroredIdpId, customZoneId)).thenReturn(mirroredIdp);

        when(mockIdentityProviderProvisioning.update(any(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        final IdentityProvider<?> requestBody = existingIdpSupplier.get();
        final String newName = "new name";
        requestBody.setName(newName);
        final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(existingIdpId, requestBody, true);
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        final IdentityProvider responseBody = response.getBody();
        Assertions.assertThat(responseBody).isNotNull();
        Assertions.assertThat(responseBody.getName()).isNotNull().isEqualTo(newName);

        final ArgumentCaptor<IdentityProvider> idpArgumentCaptor = ArgumentCaptor.forClass(IdentityProvider.class);
        verify(mockIdentityProviderProvisioning, times(2)).update(idpArgumentCaptor.capture(), anyString());

        // expecting original IdP with the new name
        final IdentityProvider firstIdp = idpArgumentCaptor.getAllValues().get(0);
        Assertions.assertThat(firstIdp).isNotNull();
        Assertions.assertThat(firstIdp.getId()).isEqualTo(existingIdpId);
        Assertions.assertThat(firstIdp.getName()).isEqualTo(newName);

        // expecting mirrored IdP with the new name
        final IdentityProvider secondIdp = idpArgumentCaptor.getAllValues().get(1);
        Assertions.assertThat(secondIdp).isNotNull();
        Assertions.assertThat(secondIdp.getId()).isEqualTo(mirroredIdpId);
        Assertions.assertThat(secondIdp.getName()).isEqualTo(newName);
    }

    @Test
    void testUpdateStatus_ShouldAlsoUpdateMirroredIdpIfPresent() {
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(UAA);

        final IdentityProvider<UaaIdentityProviderDefinition> idp = new IdentityProvider<>();
        final String idpId = UUID.randomUUID().toString();
        idp.setId(idpId);
        idp.setIdentityZoneId(UAA);
        final String mirroredIdpId = UUID.randomUUID().toString();
        idp.setAliasId(mirroredIdpId);
        final String customZoneId = UUID.randomUUID().toString();
        idp.setAliasZid(customZoneId);
        final UaaIdentityProviderDefinition config = new UaaIdentityProviderDefinition();
        final PasswordPolicy passwordPolicy = new PasswordPolicy();
        config.setPasswordPolicy(passwordPolicy);
        idp.setConfig(config);
        when(mockIdentityProviderProvisioning.retrieve(idpId, UAA)).thenReturn(idp);

        final IdentityProvider<UaaIdentityProviderDefinition> mirroredIdp = new IdentityProvider<>();
        mirroredIdp.setId(mirroredIdpId);
        mirroredIdp.setIdentityZoneId(customZoneId);
        mirroredIdp.setAliasId(idpId);
        mirroredIdp.setAliasZid(UAA);
        mirroredIdp.setConfig(config);
        when(mockIdentityProviderProvisioning.retrieve(mirroredIdpId, customZoneId)).thenReturn(mirroredIdp);

        when(mockIdentityProviderProvisioning.update(any(), anyString())).thenReturn(null);

        final Date timestampBeforeUpdate = new Date(System.currentTimeMillis());

        final IdentityProviderStatus requestBody = new IdentityProviderStatus();
        requestBody.setRequirePasswordChange(true);
        final ResponseEntity<IdentityProviderStatus> response = identityProviderEndpoints.updateIdentityProviderStatus(idpId, requestBody);

        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(response.getBody()).isNotNull().isEqualTo(requestBody);

        final ArgumentCaptor<IdentityProvider> idpArgumentCaptor = ArgumentCaptor.forClass(IdentityProvider.class);
        verify(mockIdentityProviderProvisioning, times(2)).update(idpArgumentCaptor.capture(), anyString());

        // expecting original IdP with a new timestamp
        final IdentityProvider firstIdp = idpArgumentCaptor.getAllValues().get(0);
        Assertions.assertThat(firstIdp).isNotNull();
        Assertions.assertThat(firstIdp.getId()).isEqualTo(idpId);
        final Date timestampAfterUpdateFirstIdp = ((UaaIdentityProviderDefinition) firstIdp.getConfig()).getPasswordPolicy().getPasswordNewerThan();
        Assertions.assertThat(timestampAfterUpdateFirstIdp).isNotNull().isAfter(timestampBeforeUpdate);

        // expecting mirrored IdP with same timestamp
        final IdentityProvider secondIdp = idpArgumentCaptor.getAllValues().get(1);
        Assertions.assertThat(secondIdp).isNotNull();
        Assertions.assertThat(secondIdp.getId()).isEqualTo(mirroredIdpId);
        final Date timestampAfterUpdateSecondIdp = ((UaaIdentityProviderDefinition) secondIdp.getConfig()).getPasswordPolicy().getPasswordNewerThan();
        Assertions.assertThat(timestampAfterUpdateFirstIdp).isNotNull().isEqualTo(timestampAfterUpdateSecondIdp);
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

    @Test
    void testCreateIdentityProvider_AliasPropertiesInvalid() throws MetadataProviderException {
        // (1) aliasId is not empty
        IdentityProvider<?> idp = getExternalOAuthProvider();
        idp.setAliasId(UUID.randomUUID().toString());
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(idp, true);
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);

        // (2) aliasZid set, but referenced zone does not exist
        idp = getExternalOAuthProvider();
        final String notExistingZoneId = UUID.randomUUID().toString();
        idp.setAliasZid(notExistingZoneId);
        when(mockIdentityZoneProvisioning.retrieve(notExistingZoneId)).thenThrow(ZoneDoesNotExistsException.class);
        response = identityProviderEndpoints.createIdentityProvider(idp, true);
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);

        // (3) aliasZid and IdZ equal
        idp = getExternalOAuthProvider();
        idp.setAliasZid(idp.getIdentityZoneId());
        response = identityProviderEndpoints.createIdentityProvider(idp, true);
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);

        // (4) neither IdZ nor aliasZid are "uaa"
        idp = getExternalOAuthProvider();
        final String zoneId1 = UUID.randomUUID().toString();
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId1);
        final String zoneId2 = UUID.randomUUID().toString();
        final IdentityZone zone2 = new IdentityZone();
        zone2.setId(zoneId2);
        when(mockIdentityZoneProvisioning.retrieve(zoneId2)).thenReturn(zone2);
        idp.setIdentityZoneId(zoneId1);
        idp.setAliasZid(zoneId2);
        response = identityProviderEndpoints.createIdentityProvider(idp, true);
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @Test
    void testCreateIdentityProvider_ValidAliasProperties() throws MetadataProviderException {
        // arrange custom zone exists
        final String customZoneId = UUID.randomUUID().toString();
        final IdentityZone customZone = new IdentityZone();
        customZone.setId(customZoneId);
        when(mockIdentityZoneProvisioning.retrieve(customZoneId)).thenReturn(customZone);

        final Supplier<IdentityProvider<?>> requestBodyProvider = () -> {
            final IdentityProvider<?> requestBody = getExternalOAuthProvider();
            requestBody.setId(null);
            requestBody.setAliasZid(customZoneId);
            return requestBody;
        };

        // idpProvisioning.create should return request body with new ID
        final IdentityProvider<?> createdOriginalIdp = requestBodyProvider.get();
        final String originalIdpId = UUID.randomUUID().toString();
        createdOriginalIdp.setId(originalIdpId);
        final IdpWithAliasMatcher requestBodyMatcher = new IdpWithAliasMatcher(UAA, null, null, customZoneId);

        // idpProvisioning.create should add ID to mirrored IdP
        final IdentityProvider<?> persistedMirroredIdp = requestBodyProvider.get();
        final String mirroredIdpId = UUID.randomUUID().toString();
        persistedMirroredIdp.setAliasId(originalIdpId);
        persistedMirroredIdp.setAliasZid(UAA);
        persistedMirroredIdp.setIdentityZoneId(customZoneId);
        persistedMirroredIdp.setId(mirroredIdpId);
        final IdpWithAliasMatcher mirroredIdpMatcher = new IdpWithAliasMatcher(customZoneId, null, originalIdpId, UAA);
        when(mockIdentityProviderProvisioning.create(any(), anyString())).thenAnswer(invocation -> {
            final IdentityProvider<?> idp = invocation.getArgument(0);
            final String idzId = invocation.getArgument(1);
            if (requestBodyMatcher.matches(idp) && idzId.equals(UAA)) {
                return createdOriginalIdp;
            }
            if (mirroredIdpMatcher.matches(idp) && idzId.equals(customZoneId)) {
                return persistedMirroredIdp;
            }
            return null;
        });

        // mock idpProvisioning.update
        final IdentityProvider<?> createdOriginalIdpWithAliasId = requestBodyProvider.get();
        createdOriginalIdpWithAliasId.setId(originalIdpId);
        createdOriginalIdpWithAliasId.setAliasId(mirroredIdpId);
        when(mockIdentityProviderProvisioning.update(
                argThat(new IdpWithAliasMatcher(UAA, originalIdpId, mirroredIdpId, customZoneId)),
                eq(UAA)
        )).thenReturn(createdOriginalIdpWithAliasId);

        // perform the endpoint call
        final IdentityProvider<?> requestBody = requestBodyProvider.get();
        final ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(requestBody, true);
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Assertions.assertThat(response.getBody()).isEqualTo(createdOriginalIdpWithAliasId);
    }

    private static class IdpWithAliasMatcher implements ArgumentMatcher<IdentityProvider<?>> {
        private final String identityZoneId;
        private final String id;
        private final String aliasId;
        private final String aliasZid;

        public IdpWithAliasMatcher(final String identityZoneId, final String id, final String aliasId, final String aliasZid) {
            this.identityZoneId = identityZoneId;
            this.id = id;
            this.aliasId = aliasId;
            this.aliasZid = aliasZid;
        }

        @Override
        public boolean matches(final IdentityProvider<?> argument) {
            return Objects.equals(id, argument.getId()) && Objects.equals(identityZoneId, argument.getIdentityZoneId())
                    && Objects.equals(aliasId, argument.getAliasId()) && Objects.equals(aliasZid, argument.getAliasZid());
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
    void testDeleteIdentityProviderMirrored() {
        final String idpId = UUID.randomUUID().toString();
        final String mirroredIdpId = UUID.randomUUID().toString();
        final String customZoneId = UUID.randomUUID().toString();

        final IdentityProvider<?> idp = new IdentityProvider<>();
        idp.setType(OIDC10);
        idp.setId(idpId);
        idp.setIdentityZoneId(UAA);
        idp.setAliasId(mirroredIdpId);
        idp.setAliasZid(customZoneId);
        when(mockIdentityProviderProvisioning.retrieve(idpId, UAA)).thenReturn(idp);

        final IdentityProvider<?> mirroredIdp = new IdentityProvider<>();
        mirroredIdp.setType(OIDC10);
        mirroredIdp.setId(mirroredIdpId);
        mirroredIdp.setIdentityZoneId(customZoneId);
        mirroredIdp.setAliasId(idpId);
        mirroredIdp.setAliasZid(UAA);
        when(mockIdentityProviderProvisioning.retrieve(mirroredIdpId, customZoneId)).thenReturn(mirroredIdp);

        final ApplicationEventPublisher mockEventPublisher = mock(ApplicationEventPublisher.class);
        identityProviderEndpoints.setApplicationEventPublisher(mockEventPublisher);
        doNothing().when(mockEventPublisher).publishEvent(any());

        identityProviderEndpoints.deleteIdentityProvider(idpId, true);
        final ArgumentCaptor<EntityDeletedEvent<?>> entityDeletedEventCaptor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(mockEventPublisher, times(2)).publishEvent(entityDeletedEventCaptor.capture());

        final EntityDeletedEvent<?> firstEvent = entityDeletedEventCaptor.getAllValues().get(0);
        Assertions.assertThat(firstEvent).isNotNull();
        Assertions.assertThat(firstEvent.getIdentityZoneId()).isEqualTo(UAA);
        Assertions.assertThat(((IdentityProvider<?>) firstEvent.getSource()).getId()).isEqualTo(idpId);

        final EntityDeletedEvent<?> secondEvent = entityDeletedEventCaptor.getAllValues().get(1);
        Assertions.assertThat(secondEvent).isNotNull();
        Assertions.assertThat(secondEvent.getIdentityZoneId()).isEqualTo(UAA);
        Assertions.assertThat(((IdentityProvider<?>) secondEvent.getSource()).getId()).isEqualTo(mirroredIdpId);
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
}
