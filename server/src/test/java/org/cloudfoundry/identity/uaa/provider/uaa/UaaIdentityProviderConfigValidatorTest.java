package org.cloudfoundry.identity.uaa.provider.uaa;

import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class UaaIdentityProviderConfigValidatorTest {

    UaaIdentityProviderDefinition uaaIdentityProviderDef;
    UaaIdentityProviderConfigValidator configValidator;

    @BeforeEach
    void setUp() {
        uaaIdentityProviderDef = new UaaIdentityProviderDefinition();
        uaaIdentityProviderDef.setPasswordPolicy(new PasswordPolicy(8, 8, 1, 1, 8, 1, 3));
        uaaIdentityProviderDef.setLockoutPolicy(new LockoutPolicy(1, 1, 1));
        configValidator = new UaaIdentityProviderConfigValidator();
    }

    @Test
    void nullConfigIsAllowed() {
        configValidator.validate((AbstractIdentityProviderDefinition) null);
    }

    @Test
    void nullLockoutPolicy_isAllowed() {
        uaaIdentityProviderDef.setLockoutPolicy(null);
        configValidator.validate(uaaIdentityProviderDef);
    }

    @Test
    void nullPasswordPolicy_isAllowed() {
        uaaIdentityProviderDef.setPasswordPolicy(null);
        configValidator.validate(uaaIdentityProviderDef);
    }

    @Test
    void passwordPolicyIsNotNullAndIncomplete() {
        uaaIdentityProviderDef.setPasswordPolicy(new PasswordPolicy(8, 8, -1, 1, 8, 1, 3));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                configValidator.validate(uaaIdentityProviderDef));
    }

    @Test
    void lockoutPolicyIsNotNullAndIncomplete() {
        uaaIdentityProviderDef.setLockoutPolicy(new LockoutPolicy(-1, 1, 1));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                configValidator.validate(uaaIdentityProviderDef));
    }

}
