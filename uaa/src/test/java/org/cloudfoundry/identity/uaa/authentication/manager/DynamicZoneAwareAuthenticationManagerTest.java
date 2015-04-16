package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

import static org.junit.Assert.assertSame;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class DynamicZoneAwareAuthenticationManagerTest {

    DynamicZoneAwareAuthenticationManager manager;
    IdentityProviderProvisioning providerProvisioning = mock(IdentityProviderProvisioning.class);
    LdapIdentityProviderDefinition ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
        "ldap://localhost:38889/",
        "cn=admin,ou=Users,dc=test,dc=com",
        "adminsecret",
        "dc=test,dc=com",
        "cn={0}",
        "ou=scopes,dc=test,dc=com",
        "member={0}",
        "mail",
        null,
        false,
        true,
        true,
        100,
        true);


    AuthenticationManager authzAuthenticationMgr = mock(AuthenticationManager.class);
    AuthenticationManager uaaAuthenticationMgr = mock(AuthenticationManager.class);
    ScimGroupExternalMembershipManager scimGroupExternalMembershipManager = mock(ScimGroupExternalMembershipManager.class);
    ScimGroupProvisioning scimGroupProvisioning = mock(ScimGroupProvisioning.class);
    LdapLoginAuthenticationManager ldapLoginAuthenticationManager = mock(LdapLoginAuthenticationManager.class);


    @Before
    @After
    public void clearIdentityZoneHolder() throws Exception {

        IdentityZoneHolder.clear();
    }

    @Test
    public void testAuthenticateInUaaZone() throws Exception {
        Authentication success = mock(Authentication.class);
        when(success.isAuthenticated()).thenReturn(true);
        when(authzAuthenticationMgr.authenticate(any(Authentication.class))).thenReturn(success);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager();
        Authentication result = manager.authenticate(null);
        assertSame(success, result);
        verifyZeroInteractions(uaaAuthenticationMgr);
    }

    @Test
    public void testAuthenticateInNoneUaaZoneWithLdapProvider() throws Exception {
        Authentication success = mock(Authentication.class);
        when(success.isAuthenticated()).thenReturn(true);
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("test","test"));

        IdentityProvider ldapProvider = new IdentityProvider();
        ldapProvider.setActive(true);
        ldapProvider.setConfig(JsonUtils.writeValueAsString(ldapIdentityProviderDefinition));
        when(providerProvisioning.retrieveByOrigin(Origin.LDAP, "test")).thenReturn(ldapProvider);

        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);

        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        when(mockManager.authenticate(eq(success))).thenReturn(success);
        when(mockManager.getDefinition()).thenReturn(ldapIdentityProviderDefinition);
        Authentication result = manager.authenticate(success);
        assertSame(success, result);
        verifyZeroInteractions(uaaAuthenticationMgr);
        verifyZeroInteractions(authzAuthenticationMgr);
    }

    @Test
    public void testAuthenticateInNoneUaaZoneWithInactiveLdapProvider() throws Exception {
        Authentication success = mock(Authentication.class);
        when(success.isAuthenticated()).thenReturn(true);
        when(uaaAuthenticationMgr.authenticate(any(Authentication.class))).thenReturn(success);

        IdentityZoneHolder.set(MultitenancyFixture.identityZone("test","test"));

        IdentityProvider ldapProvider = new IdentityProvider();
        ldapProvider.setActive(false);
        ldapProvider.setConfig(JsonUtils.writeValueAsString(ldapIdentityProviderDefinition));
        when(providerProvisioning.retrieveByOrigin(Origin.LDAP, "test")).thenReturn(ldapProvider);

        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager();

        Authentication result = manager.authenticate(null);
        assertSame(success, result);

        verifyZeroInteractions(authzAuthenticationMgr);
    }

    protected DynamicZoneAwareAuthenticationManager getDynamicZoneAwareAuthenticationManager() {
        return getDynamicZoneAwareAuthenticationManager(false);
    }
    protected DynamicZoneAwareAuthenticationManager getDynamicZoneAwareAuthenticationManager(boolean mock) {
        if (mock) {
            final DynamicLdapAuthenticationManager mockLdapManager = mock(DynamicLdapAuthenticationManager.class);
            return new DynamicZoneAwareAuthenticationManager(
                authzAuthenticationMgr,
                providerProvisioning,
                uaaAuthenticationMgr,
                scimGroupExternalMembershipManager,
                scimGroupProvisioning,
                ldapLoginAuthenticationManager
            ) {
                @Override
                protected DynamicLdapAuthenticationManager getLdapAuthenticationManager(IdentityZone zone, IdentityProvider provider) {
                    return mockLdapManager;
                }
            };

        } else {
            return new DynamicZoneAwareAuthenticationManager(
                authzAuthenticationMgr,
                providerProvisioning,
                uaaAuthenticationMgr,
                scimGroupExternalMembershipManager,
                scimGroupProvisioning,
                ldapLoginAuthenticationManager
            );
        }
    }


}