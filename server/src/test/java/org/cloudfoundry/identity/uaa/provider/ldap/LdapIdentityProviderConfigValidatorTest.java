package org.cloudfoundry.identity.uaa.provider.ldap;


import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class LdapIdentityProviderConfigValidatorTest {


    @Rule
    public ExpectedException exception = ExpectedException.none();

    LdapIdentityProviderConfigValidator validator;

    @Before
    public void setup() {
        validator = spy(new LdapIdentityProviderConfigValidator());
    }

    @Test
    public void null_identity_provider() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Provider cannot be null");
        validator.validate((IdentityProvider<AbstractIdentityProviderDefinition>) null);
    }

    @Test
    public void invalid_ldap_origin() {
        IdentityProvider<LdapIdentityProviderDefinition> ldap = new IdentityProvider<>();
        ldap.setType(LDAP);
        ldap.setOriginKey("other");
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage(String.format("LDAP provider originKey must be set to '%s'", LDAP));
        validator.validate(ldap);
    }


    @Test
    public void valid_ldap_origin() {
        IdentityProvider<LdapIdentityProviderDefinition> ldap = new IdentityProvider<>();
        ldap.setType(LDAP);
        ldap.setOriginKey(LDAP);
        doNothing().when(validator).validate(any(AbstractIdentityProviderDefinition.class));
        validator.validate(ldap);
        verify(validator, times(1)).validate((AbstractIdentityProviderDefinition) isNull());

    }
}