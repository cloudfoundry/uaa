package org.cloudfoundry.identity.uaa.provider.uaa;

import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.junit.Before;
import org.junit.Test;

public class UaaIdentityProviderConfigValidatorTest {

    UaaIdentityProviderDefinition uaaIdentityProviderDef;
    UaaIdentityProviderConfigValidator configValidator;

    @Before
    public void setUp() {
        uaaIdentityProviderDef = new UaaIdentityProviderDefinition();
        uaaIdentityProviderDef.setPasswordPolicy(new PasswordPolicy(8, 8, 1, 1, 8, 1, 3));
        uaaIdentityProviderDef.setLockoutPolicy(new LockoutPolicy(1, 1, 1));
        configValidator = new UaaIdentityProviderConfigValidator();
    }

    @Test
    public void nullConfigIsAllowed() {
        configValidator.validate((AbstractIdentityProviderDefinition) null);
    }

    @Test
    public void nullLockoutPolicy_isAllowed() {
        uaaIdentityProviderDef.setLockoutPolicy(null);
        configValidator.validate(uaaIdentityProviderDef);
    }

    @Test
    public void nullPasswordPolicy_isAllowed() {
        uaaIdentityProviderDef.setPasswordPolicy(null);
        configValidator.validate(uaaIdentityProviderDef);
    }

    @Test(expected = IllegalArgumentException.class)
    public void passwordPolicyIsNotNullAndIncomplete() {
        uaaIdentityProviderDef.setPasswordPolicy(new PasswordPolicy(8, 8, -1, 1, 8, 1, 3));
        configValidator.validate(uaaIdentityProviderDef);
    }

    @Test(expected = IllegalArgumentException.class)
    public void lockoutPolicyIsNotNullAndIncomplete() {
        uaaIdentityProviderDef.setLockoutPolicy(new LockoutPolicy(-1, 1, 1));
        configValidator.validate(uaaIdentityProviderDef);
    }

}
