package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class DynamicZoneAwareAuthenticationManagerTest {

    private static final IdentityZone ZONE = MultitenancyFixture.identityZone("test", "test");
    private final IdentityProviderProvisioning providerProvisioning = mock(IdentityProviderProvisioning.class);
    private final LdapIdentityProviderDefinition ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
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


    private final AuthenticationManager uaaAuthenticationMgr = mock(AuthenticationManager.class);
    private final ScimGroupExternalMembershipManager scimGroupExternalMembershipManager = mock(ScimGroupExternalMembershipManager.class);
    private final ScimGroupProvisioning scimGroupProvisioning = mock(ScimGroupProvisioning.class);
    private final LdapLoginAuthenticationManager ldapLoginAuthenticationManager = mock(LdapLoginAuthenticationManager.class);
    private final Authentication success = mock(Authentication.class);
    private final IdentityProvider uaaActive = mock(IdentityProvider.class);
    private final IdentityProvider uaaInactive = mock(IdentityProvider.class);
    private final IdentityProvider ldapActive = mock(IdentityProvider.class);
    private final IdentityProvider ldapInactive = mock(IdentityProvider.class);

    @BeforeEach
    @AfterEach
    void beforeAndAfter() {
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
    void authenticateInUaaZone() {
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager();
        Authentication result = manager.authenticate(null);
        assertThat(result).isNull();
        verifyNoInteractions(uaaAuthenticationMgr);
    }

    @Test
    void nonUAAZoneUaaNotActive() {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaInactive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        when(mockManager.authenticate(any(Authentication.class))).thenReturn(success);
        when(mockManager.getDefinition()).thenReturn(ldapIdentityProviderDefinition);
        Authentication result = manager.authenticate(success);
        assertThat(result).isSameAs(success);
        verifyNoInteractions(uaaAuthenticationMgr);
    }

    @Test
    void nonUAAZoneUaaActiveAccountNotVerified() {
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
    void nonUAAZoneUaaActiveAccountLocked() {
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
    void nonUAAZoneUaaActiveUaaAuthenticationSuccess() {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaActive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        when(uaaAuthenticationMgr.authenticate(any(Authentication.class))).thenReturn(success);
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        assertThat(manager.authenticate(success)).isSameAs(success);
        verify(mockManager, times(0)).authenticate(any(Authentication.class));
    }

    @Test
    void nonUAAZoneUaaActiveUaaAuthenticationFailure() {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaActive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        when(uaaAuthenticationMgr.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("mock"));
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        when(mockManager.authenticate(any(Authentication.class))).thenReturn(success);
        assertThat(manager.authenticate(success)).isSameAs(success);
    }

    @Test
    void authenticateInNoneUaaZoneWithLdapProvider() {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaInactive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        when(mockManager.authenticate(any(Authentication.class))).thenReturn(success);
        when(mockManager.getDefinition()).thenReturn(ldapIdentityProviderDefinition);
        Authentication result = manager.authenticate(success);
        assertThat(result).isSameAs(success);
        verifyNoInteractions(uaaAuthenticationMgr);
    }

    @Test
    void authenticateInNoneUaaZoneWithInactiveProviders() {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapInactive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaInactive);
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        DynamicLdapAuthenticationManager mockManager = manager.getLdapAuthenticationManager(null, null);
        when(mockManager.authenticate(any(Authentication.class))).thenReturn(success);
        when(mockManager.getDefinition()).thenReturn(ldapIdentityProviderDefinition);
        try {
            manager.authenticate(success);
            fail("Was expecting a " + ProviderNotFoundException.class);
        } catch (ProviderNotFoundException x) {
            //expected
        }
        verifyNoInteractions(uaaAuthenticationMgr);
        verifyNoInteractions(mockManager);
    }

    @Test
    void extractLoginHint() {
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);

        UaaAuthenticationDetails mockDetails = mock(UaaAuthenticationDetails.class);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("uaa");
        when(success.getDetails()).thenReturn(mockDetails);

        assertThat(manager.extractLoginHint(null)).isNull();
        assertThat(manager.extractLoginHint(success)).isNull();

        when(mockDetails.getLoginHint()).thenReturn(loginHint);
        assertThat(manager.extractLoginHint(success)).isEqualTo(loginHint);
    }

    @Test
    void invalidLoginHint() {
        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidc");
        try {
            manager.getChainedAuthenticationManager(IdentityZone.getUaa(), loginHint);
            fail("");
        } catch (ProviderNotFoundException e) {
            assertThat(e.getMessage()).isEqualTo("The origin provided in the login hint is invalid.");
        }
    }

    @Test
    void loginHintUaa() {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaActive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);

        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("uaa");
        ChainedAuthenticationManager chainedAuthenticationManager = manager.getChainedAuthenticationManager(ZONE, loginHint);

        assertThat(chainedAuthenticationManager.getDelegates().length).isOne();
        assertThat(chainedAuthenticationManager.getDelegates()[0].getAuthenticationManager()).isEqualTo(uaaAuthenticationMgr);
    }

    @Test
    void loginHintLdap() {
        IdentityZoneHolder.set(ZONE);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, ZONE.getId())).thenReturn(uaaActive);
        when(providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, ZONE.getId())).thenReturn(ldapActive);

        DynamicZoneAwareAuthenticationManager manager = getDynamicZoneAwareAuthenticationManager(true);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("ldap");
        ChainedAuthenticationManager chainedAuthenticationManager = manager.getChainedAuthenticationManager(ZONE, loginHint);

        assertThat(chainedAuthenticationManager.getDelegates().length).isOne();
        assertThat(chainedAuthenticationManager.getDelegates()[0].getAuthenticationManager()).isEqualTo(manager.getLdapAuthenticationManager(ZONE, ldapActive));
    }

    DynamicZoneAwareAuthenticationManager getDynamicZoneAwareAuthenticationManager() {
        return getDynamicZoneAwareAuthenticationManager(false);
    }

    DynamicZoneAwareAuthenticationManager getDynamicZoneAwareAuthenticationManager(boolean mock) {
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
