package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class DynamicZoneAwareAuthenticationManagerTest {

    public static final IdentityZone ZONE = MultitenancyFixture.identityZone("test", "test");
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


    AuthenticationManager uaaAuthenticationMgr = mock(AuthenticationManager.class);
    ScimGroupExternalMembershipManager scimGroupExternalMembershipManager = mock(ScimGroupExternalMembershipManager.class);
    ScimGroupProvisioning scimGroupProvisioning = mock(ScimGroupProvisioning.class);
    LdapLoginAuthenticationManager ldapLoginAuthenticationManager = mock(LdapLoginAuthenticationManager.class);
    Authentication success = mock(Authentication.class);
    IdentityProvider uaaActive = mock(IdentityProvider.class);
    IdentityProvider uaaInactive = mock(IdentityProvider.class);
    IdentityProvider ldapActive = mock(IdentityProvider.class);
    IdentityProvider ldapInactive = mock(IdentityProvider.class);



    @Before
    @After
    public void beforeAndAfter() throws Exception {
        when(success.isAuthenticated()).thenReturn(true);

        when(uaaActive.isActive()).thenReturn(true);
        when(uaaActive.getOriginKey()).thenReturn(OriginKeys.UAA);
        when(uaaInactive.isActive()).thenReturn(false);
        when(uaaInactive.getOriginKey()).thenReturn(OriginKeys.UAA);

        when(ldapActive.isActive()).thenReturn(true);
        when(ldapActive.getOriginKey()).thenReturn(OriginKeys.LDAP);
        when(ldapInactive.isActive()).thenReturn(false);
        when(ldapInactive.getOriginKey()).thenReturn(OriginKeys.LDAP);
        when(ldapActive.getConfig()).thenReturn(ldapIdentityProviderDefinition);
        when(ldapActive.getConfig()).thenReturn(ldapIdentityProviderDefinition);

        IdentityZoneHolder.clear();
    }

    @Test
    public void testAuthenticateInUaaZone() throws Exception {
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager();
        Authentication result = manager.authenticate(null);
        assertNull(result);
        verifyZeroInteractions(uaaAuthenticationMgr);
    }

    @Test
    public void testNonUAAZoneUaaNotActive() throws Exception {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaInactive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        when(mockManager.authenticate(any(Authentication.class))).thenReturn(success);
        when(mockManager.getDefinition()).thenReturn(ldapIdentityProviderDefinition);
        Authentication result = manager.authenticate(success);
        assertSame(success, result);
        verifyZeroInteractions(uaaAuthenticationMgr);
    }

    @Test
    public void testNonUAAZoneUaaActiveAccountNotVerified() throws Exception {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaActive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        when(uaaAuthenticationMgr.authenticate(any(Authentication.class))).thenThrow(new AccountNotVerifiedException("mock"));
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        try {
            manager.authenticate(success);
            fail("Expected AccountNotVerifiedException ");
        } catch (AccountNotVerifiedException x) {
            //expected
        }
        verify(mockManager, times(0)).authenticate(any(Authentication.class));
    }

    @Test
    public void testNonUAAZoneUaaActiveAccountLocked() throws Exception {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaActive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        when(uaaAuthenticationMgr.authenticate(any(Authentication.class))).thenThrow(new AuthenticationPolicyRejectionException("mock"));
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        try {
            manager.authenticate(success);
            fail("Expected AuthenticationPolicyRejectionException ");
        } catch (AuthenticationPolicyRejectionException x) {
            //expected
        }
        verify(mockManager, times(0)).authenticate(any(Authentication.class));
    }

    @Test
    public void testNonUAAZoneUaaActiveUaaAuthenticationSucccess() throws Exception {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaActive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        when(uaaAuthenticationMgr.authenticate(any(Authentication.class))).thenReturn(success);
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        assertSame(success, manager.authenticate(success));
        verify(mockManager, times(0)).authenticate(any(Authentication.class));
    }

    @Test
    public void testNonUAAZoneUaaActiveUaaAuthenticationFailure() throws Exception {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaActive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        when(uaaAuthenticationMgr.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("mock"));
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        when(mockManager.authenticate(any(Authentication.class))).thenReturn(success);
        assertSame(success, manager.authenticate(success));
    }

    @Test
    public void testAuthenticateInNoneUaaZoneWithLdapProvider() throws Exception {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaInactive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        when(mockManager.authenticate(any(Authentication.class))).thenReturn(success);
        when(mockManager.getDefinition()).thenReturn(ldapIdentityProviderDefinition);
        Authentication result = manager.authenticate(success);
        assertSame(success, result);
        verifyZeroInteractions(uaaAuthenticationMgr);
    }

    @Test
    public void testAuthenticateInNoneUaaZoneWithInactiveProviders() throws Exception {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapInactive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaInactive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        when(mockManager.authenticate(any(Authentication.class))).thenReturn(success);
        when(mockManager.getDefinition()).thenReturn(ldapIdentityProviderDefinition);
        try {
            manager.authenticate(success);
            fail("Was expecting a "+ProviderNotFoundException.class);
        } catch (ProviderNotFoundException x) {
            //expected
        }
        verifyZeroInteractions(uaaAuthenticationMgr);
        verifyZeroInteractions(mockManager);
    }

    protected DynamicZoneAwareAuthenticationManager getDynamicZoneAwareAuthenticationManager() {
        return getDynamicZoneAwareAuthenticationManager(false);
    }
    protected DynamicZoneAwareAuthenticationManager getDynamicZoneAwareAuthenticationManager(boolean mock) {
        if (mock) {
            final DynamicLdapAuthenticationManager mockLdapManager = mock(DynamicLdapAuthenticationManager.class);
            return new DynamicZoneAwareAuthenticationManager(
                providerProvisioning,
                uaaAuthenticationMgr,
                scimGroupExternalMembershipManager,
                scimGroupProvisioning,
                ldapLoginAuthenticationManager
            ) {
                @Override
                public DynamicLdapAuthenticationManager getLdapAuthenticationManager(IdentityZone zone, IdentityProvider provider) {
                    when(mockLdapManager.getDefinition()).thenReturn(ldapIdentityProviderDefinition);
                    return mockLdapManager;
                }
            };

        } else {
            return new DynamicZoneAwareAuthenticationManager(
                providerProvisioning,
                uaaAuthenticationMgr,
                scimGroupExternalMembershipManager,
                scimGroupProvisioning,
                ldapLoginAuthenticationManager
            );
        }
    }


}
