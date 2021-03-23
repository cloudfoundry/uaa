package org.cloudfoundry.identity.uaa.provider.uaa;

import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.BaseIdentityProviderValidator;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.springframework.stereotype.Component;

@Component
public class UaaIdentityProviderConfigValidator extends BaseIdentityProviderValidator {

    @Override
    public void validate(AbstractIdentityProviderDefinition definition) {
        if (definition == null) {
            return;
        }
        UaaIdentityProviderDefinition def = (UaaIdentityProviderDefinition) definition;

        PasswordPolicy passwordPolicy = def.getPasswordPolicy();
        LockoutPolicy lockoutPolicy = def.getLockoutPolicy();

        if (passwordPolicy == null && lockoutPolicy == null) {
            return;
        } else {
            boolean isValid = true;
            if (passwordPolicy != null) {
                isValid = passwordPolicy.allPresentAndPositive();
            }
            if (lockoutPolicy != null) {
                isValid = isValid && lockoutPolicy.allPresentAndPositive();
            }

            if (!isValid) {
                throw new IllegalArgumentException("Invalid Password/Lockout policy");
            }
        }
    }
}
