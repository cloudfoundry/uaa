package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UNKNOWN;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class IdentityProviderEndpointsTest {

    private IdentityProviderEndpoints identityProviderEndpoints;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private ScimGroupExternalMembershipManager scimGroupExternalMembershipManager;
    private ScimGroupProvisioning scimGroupProvisioning;
    private SamlIdentityProviderConfigurator samlConfigurator;
    private IdentityProviderConfigValidationDelegator configValidator;

    @Before
    public void setup() {

        configValidator = mock(IdentityProviderConfigValidationDelegator.class);
        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        identityProviderEndpoints = new IdentityProviderEndpoints(identityProviderProvisioning, scimGroupExternalMembershipManager, scimGroupProvisioning, samlConfigurator, configValidator);
    }

    public IdentityProvider<AbstractXOAuthIdentityProviderDefinition> getXOAuthProvider() {
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
            config.setUserInfoUrl(new URL(urlBase+"/userinfo"));
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
        identityProvider.setIdentityZoneId(IdentityZone.getUaa().getId());
        return identityProvider;
    }


    public IdentityProvider<LdapIdentityProviderDefinition> getLdapDefinition() {
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
    public void retrieve_oauth_provider_by_id_redacts_password() throws Exception {
        retrieve_oauth_provider_by_id("", OriginKeys.OAUTH20);
        retrieve_oauth_provider_by_id("", OriginKeys.OIDC10);
    }

    public IdentityProvider<LdapIdentityProviderDefinition> retrieve_oauth_provider_by_id(String id, String type) throws Exception {
        IdentityProvider provider = getXOAuthProvider();
        provider.setType(type);
        when(identityProviderProvisioning.retrieve(anyString())).thenReturn(provider);
        ResponseEntity<IdentityProvider> oauth = identityProviderEndpoints.retrieveIdentityProvider(id, true);
        assertNotNull(oauth);
        assertEquals(200,oauth.getStatusCode().value());
        assertNotNull(oauth.getBody());
        assertNotNull(oauth.getBody().getConfig());
        assertTrue(oauth.getBody().getConfig() instanceof AbstractXOAuthIdentityProviderDefinition);
        assertNull(((AbstractXOAuthIdentityProviderDefinition)oauth.getBody().getConfig()).getRelyingPartySecret());
        return oauth.getBody();
    }

    @Test
    public void retrieve_ldap_provider_by_id_redacts_password() throws Exception {
        retrieve_ldap_provider_by_id("");
    }

    public IdentityProvider<LdapIdentityProviderDefinition> retrieve_ldap_provider_by_id(String id) throws Exception {
        when(identityProviderProvisioning.retrieve(anyString())).thenReturn(getLdapDefinition());
        ResponseEntity<IdentityProvider> ldap = identityProviderEndpoints.retrieveIdentityProvider(id, true);
        assertNotNull(ldap);
        assertEquals(200,ldap.getStatusCode().value());
        assertNotNull(ldap.getBody());
        assertNotNull(ldap.getBody().getConfig());
        assertTrue(ldap.getBody().getConfig() instanceof LdapIdentityProviderDefinition);
        assertNull(((LdapIdentityProviderDefinition)ldap.getBody().getConfig()).getBindPassword());
        return ldap.getBody();
    }

    @Test
    public void remove_bind_password() throws Exception {
        remove_sensitive_data(() -> getLdapDefinition(),
                              LDAP,
                              (spy) -> verify((LdapIdentityProviderDefinition)spy, times(1)).setBindPassword(Matchers.isNull(String.class)));
    }

    @Test
    public void remove_client_secret() throws Exception {
        for (String type : Arrays.asList(OIDC10, OAUTH20)) {
            remove_sensitive_data(() -> getXOAuthProvider(),
                                  type,
                                  (spy) -> verify((AbstractXOAuthIdentityProviderDefinition)spy, times(1)).setRelyingPartySecret(Matchers.isNull(String.class)));
        }
    }

    public void remove_sensitive_data(Supplier<IdentityProvider> getProvider, String type, Consumer<AbstractIdentityProviderDefinition> validator) {
        IdentityProvider provider = getProvider.get();
        AbstractIdentityProviderDefinition spy = Mockito.spy(provider.getConfig());
        provider.setConfig(spy);
        provider.setType(type);
        identityProviderEndpoints.redactSensitiveData(provider);
        validator.accept(spy);

    }

    @Test
    public void remove_client_secret_wrong_origin() throws Exception {
        IdentityProvider provider = getXOAuthProvider();
        AbstractXOAuthIdentityProviderDefinition spy = Mockito.spy((AbstractXOAuthIdentityProviderDefinition) provider.getConfig());
        provider.setConfig(spy);
        provider.setType(UNKNOWN);
        identityProviderEndpoints.redactSensitiveData(provider);
        verify(spy, never()).setRelyingPartySecret(Matchers.isNull(String.class));
    }

    @Test
    public void remove_bind_password_non_ldap() throws Exception {
        IdentityProvider provider = getLdapDefinition();
        LdapIdentityProviderDefinition spy = Mockito.spy((LdapIdentityProviderDefinition)provider.getConfig());
        provider.setConfig(spy);
        provider.setType(OriginKeys.UNKNOWN);
        identityProviderEndpoints.redactSensitiveData(provider);
        verify(spy, never()).setBindPassword(Matchers.isNull(String.class));
    }

    @Test
    public void patch_bind_password() throws Exception {
        IdentityProvider provider = getLdapDefinition();
        LdapIdentityProviderDefinition def = (LdapIdentityProviderDefinition) provider.getConfig();
        def.setBindPassword(null);
        LdapIdentityProviderDefinition spy = Mockito.spy(def);
        provider.setConfig(spy);
        reset(identityProviderProvisioning);
        when(identityProviderProvisioning.retrieve(eq(provider.getId()))).thenReturn(getLdapDefinition());
        identityProviderEndpoints.patchSensitiveData(provider.getId(), provider);
        verify(spy, times(1)).setBindPassword(eq(getLdapDefinition().getConfig().getBindPassword()));
    }

    @Test
    public void patch_client_secret() throws Exception {
        for (String type : Arrays.asList(OIDC10, OAUTH20)) {
            IdentityProvider<AbstractXOAuthIdentityProviderDefinition> provider = getXOAuthProvider();
            AbstractXOAuthIdentityProviderDefinition def = provider.getConfig();
            def.setRelyingPartySecret(null);
            AbstractXOAuthIdentityProviderDefinition spy = Mockito.spy(def);
            provider.setConfig(spy);
            provider.setType(type);
            reset(identityProviderProvisioning);
            when(identityProviderProvisioning.retrieve(eq(provider.getId()))).thenReturn(getXOAuthProvider());
            identityProviderEndpoints.patchSensitiveData(provider.getId(), provider);
            verify(spy, times(1)).setRelyingPartySecret(eq(getXOAuthProvider().getConfig().getRelyingPartySecret()));
        }
    }

    @Test
    public void patch_bind_password_non_ldap() throws Exception {
        IdentityProvider provider = getLdapDefinition();
        LdapIdentityProviderDefinition spy = Mockito.spy((LdapIdentityProviderDefinition)provider.getConfig());
        provider.setConfig(spy);
        provider.setType(OriginKeys.UNKNOWN);
        identityProviderEndpoints.redactSensitiveData(provider);
        verify(spy, never()).setBindPassword(anyObject());
    }

    @Test
    public void retrieve_all_providers_redacts_data() throws Exception {
        when(identityProviderProvisioning.retrieveAll(anyBoolean(), anyString()))
            .thenReturn(Arrays.asList(getLdapDefinition(), getXOAuthProvider()));
        ResponseEntity<List<IdentityProvider>> ldapList = identityProviderEndpoints.retrieveIdentityProviders("false", true);
        assertNotNull(ldapList);
        assertNotNull(ldapList.getBody());
        assertEquals(2, ldapList.getBody().size());
        IdentityProvider<LdapIdentityProviderDefinition> ldap = ldapList.getBody().get(0);
        assertNotNull(ldap);
        assertNotNull(ldap.getConfig());
        assertTrue(ldap.getConfig() instanceof LdapIdentityProviderDefinition);
        assertNull(ldap.getConfig().getBindPassword());

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oauth = ldapList.getBody().get(1);
        assertNotNull(oauth);
        assertNotNull(oauth.getConfig());
        assertTrue(oauth.getConfig() instanceof AbstractXOAuthIdentityProviderDefinition);
        assertNull(oauth.getConfig().getRelyingPartySecret());
    }

    @Test
    public void update_ldap_provider_patches_password() throws Exception {
        IdentityProvider<LdapIdentityProviderDefinition> provider = retrieve_ldap_provider_by_id("id");
        provider.getConfig().setBindPassword(null);
        LdapIdentityProviderDefinition spy = Mockito.spy(provider.getConfig());
        provider.setConfig(spy);
        reset(identityProviderProvisioning);
        when(identityProviderProvisioning.retrieve(eq(provider.getId()))).thenReturn(getLdapDefinition());
        when(identityProviderProvisioning.update(anyObject())).thenReturn(getLdapDefinition());
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(provider.getId(), provider, true);
        verify(spy, times(1)).setBindPassword(eq(getLdapDefinition().getConfig().getBindPassword()));
        ArgumentCaptor<IdentityProvider> captor = ArgumentCaptor.forClass(IdentityProvider.class);
        verify(identityProviderProvisioning, times(1)).update(captor.capture());
        assertNotNull(captor.getValue());
        assertEquals(1, captor.getAllValues().size());
        assertEquals(getLdapDefinition().getConfig().getBindPassword(), ((LdapIdentityProviderDefinition)captor.getValue().getConfig()).getBindPassword());
        assertNotNull(response);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().getConfig());
        assertTrue(response.getBody().getConfig() instanceof LdapIdentityProviderDefinition);
        assertNull(((LdapIdentityProviderDefinition)response.getBody().getConfig()).getBindPassword());
    }

    @Test
    public void update_ldap_provider_takes_new_password() throws Exception {
        IdentityProvider<LdapIdentityProviderDefinition> provider = retrieve_ldap_provider_by_id("id");
        LdapIdentityProviderDefinition spy = Mockito.spy(provider.getConfig());
        provider.setConfig(spy);
        spy.setBindPassword("newpassword");
        reset(identityProviderProvisioning);
        when(identityProviderProvisioning.retrieve(eq(provider.getId()))).thenReturn(getLdapDefinition());
        when(identityProviderProvisioning.update(anyObject())).thenReturn(getLdapDefinition());
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.updateIdentityProvider(provider.getId(), provider, true);
        verify(spy, times(1)).setBindPassword(eq("newpassword"));
        ArgumentCaptor<IdentityProvider> captor = ArgumentCaptor.forClass(IdentityProvider.class);
        verify(identityProviderProvisioning, times(1)).update(captor.capture());
        assertNotNull(captor.getValue());
        assertEquals(1, captor.getAllValues().size());
        assertEquals("newpassword", ((LdapIdentityProviderDefinition)captor.getValue().getConfig()).getBindPassword());

        assertNotNull(response);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().getConfig());
        assertTrue(response.getBody().getConfig() instanceof LdapIdentityProviderDefinition);
        assertNull(((LdapIdentityProviderDefinition)response.getBody().getConfig()).getBindPassword());
    }

    @Test
    public void create_ldap_provider_removes_password() throws Exception {
        IdentityProvider<LdapIdentityProviderDefinition> ldapDefinition = getLdapDefinition();
        assertNotNull(ldapDefinition.getConfig().getBindPassword());
        when(identityProviderProvisioning.create(anyObject())).thenReturn(ldapDefinition);
        ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(ldapDefinition, true);
        IdentityProvider created = response.getBody();
        assertNotNull(created);
        assertEquals(LDAP, created.getType());
        assertNotNull(created.getConfig());
        assertTrue(created.getConfig() instanceof LdapIdentityProviderDefinition);
        assertNull(((LdapIdentityProviderDefinition)created.getConfig()).getBindPassword());
    }

    @Test
    public void create_oauth_provider_removes_password() throws Exception {
        for (String type : Arrays.asList(OIDC10, OAUTH20)) {
            IdentityProvider<AbstractXOAuthIdentityProviderDefinition> xoauthDefinition = getXOAuthProvider();
            assertNotNull(xoauthDefinition.getConfig().getRelyingPartySecret());
            xoauthDefinition.setType(type);
            when(identityProviderProvisioning.create(anyObject())).thenReturn(xoauthDefinition);
            ResponseEntity<IdentityProvider> response = identityProviderEndpoints.createIdentityProvider(xoauthDefinition, true);
            IdentityProvider created = response.getBody();
            assertNotNull(created);
            assertEquals(type, created.getType());
            assertNotNull(created.getConfig());
            assertTrue(created.getConfig() instanceof AbstractXOAuthIdentityProviderDefinition);
            assertNull(((AbstractXOAuthIdentityProviderDefinition) created.getConfig()).getRelyingPartySecret());
        }
    }

    @Test
    public void testPatchIdentityProviderStatusInvalidPayload () {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntity.getStatusCode());
    }

    @Test
    public void testPatchIdentityProviderStatusInvalidIDP () {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider notUAAIDP = new IdentityProvider();
        notUAAIDP.setType("NOT_UAA");
        notUAAIDP.setConfig(new SamlIdentityProviderDefinition());
        when(identityProviderProvisioning.retrieve(anyString())).thenReturn(notUAAIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntity.getStatusCode());
    }

    @Test
    public void testPatchIdentityProviderStatusWithNoIDPDefinition () {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider invalidIDP = new IdentityProvider();
        invalidIDP.setConfig(null);
        invalidIDP.setType(OriginKeys.UAA);
        when(identityProviderProvisioning.retrieve(anyString())).thenReturn(invalidIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntity.getStatusCode());
    }

    @Test
    public void testPatchIdentityProviderStatusWithNoPasswordPolicy () {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider invalidIDP = new IdentityProvider();
        invalidIDP.setType(OriginKeys.UAA);
        invalidIDP.setConfig(new UaaIdentityProviderDefinition(null, null));
        when(identityProviderProvisioning.retrieve(anyString())).thenReturn(invalidIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntity.getStatusCode());
    }

    @Test
    public void testPatchIdentityProviderStatus () {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider validIDP = new IdentityProvider();
        validIDP.setType(OriginKeys.UAA);
        validIDP.setConfig(new UaaIdentityProviderDefinition(new PasswordPolicy(), null));
        when(identityProviderProvisioning.retrieve(anyString())).thenReturn(validIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }
}