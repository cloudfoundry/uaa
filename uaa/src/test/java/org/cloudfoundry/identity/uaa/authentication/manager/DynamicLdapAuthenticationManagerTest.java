package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class DynamicLdapAuthenticationManagerTest {

    LdapIdentityProviderDefinition ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
        "ldap://localhost:389/",
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

    @Test
    public void testGetLdapAuthenticationManager() {
        ScimGroupExternalMembershipManager scimGroupExternalMembershipManager = mock(ScimGroupExternalMembershipManager.class);
        ScimGroupProvisioning scimGroupProvisioning = mock(ScimGroupProvisioning.class);
        LdapLoginAuthenticationManager ldapLoginAuthenticationManager = mock(LdapLoginAuthenticationManager.class);
        AuthenticationManager manager =
            new DynamicLdapAuthenticationManager(ldapIdentityProviderDefinition,
                scimGroupExternalMembershipManager,
                scimGroupProvisioning,
                ldapLoginAuthenticationManager)
            .getLdapAuthenticationManager();
        assertNotNull(manager);
        assertTrue(manager instanceof ChainedAuthenticationManager);
        ChainedAuthenticationManager chainedAuthenticationManager = (ChainedAuthenticationManager)manager;
        ProviderManager providerManager = (ProviderManager)chainedAuthenticationManager.getDelegates()[0].getAuthenticationManager();
        assertEquals(1, providerManager.getProviders().size());
        assertTrue(providerManager.getProviders().get(0) instanceof LdapAuthenticationProvider);
    }
}
