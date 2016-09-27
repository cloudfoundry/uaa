package org.cloudfoundry.identity.uaa.scim.validate;

import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.passay.DigitCharacterRule;
import org.passay.LengthRule;
import org.passay.LowercaseCharacterRule;
import org.passay.PasswordData;
import org.passay.Rule;
import org.passay.RuleResult;
import org.passay.SpecialCharacterRule;
import org.passay.UppercaseCharacterRule;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * ****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
public class UaaPasswordPolicyValidator implements PasswordValidator {

    private final IdentityProviderProvisioning provisioning;
    private final PasswordPolicy globalDefaultPolicy;

    public UaaPasswordPolicyValidator(PasswordPolicy globalDefaultPolicy, IdentityProviderProvisioning provisioning) {
        this.globalDefaultPolicy = globalDefaultPolicy;
        this.provisioning = provisioning;
    }

    @Override
    public PasswordPolicy getPasswordPolicy() {
        IdentityProvider<UaaIdentityProviderDefinition> idp = provisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        if (idp==null) {
            //should never happen
            return null;
        }

        PasswordPolicy policy = globalDefaultPolicy;

        UaaIdentityProviderDefinition idpDefinition = idp.getConfig();
        if (idpDefinition != null && idpDefinition.getPasswordPolicy() != null) {
            policy = idpDefinition.getPasswordPolicy();
        }

        return policy;
    }

    @Override
    public void validate(String password) throws InvalidPasswordException {
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }

        PasswordPolicy policy = getPasswordPolicy();
        if (policy == null) {
            return;
        }

        org.passay.PasswordValidator validator = getPasswordValidator(policy);
        RuleResult result = validator.validate(new PasswordData(password));
        if (!result.isValid()) {
            List<String> errorMessages = new LinkedList<>();
            for (String s : validator.getMessages(result)) {
                errorMessages.add(s);
            }
            if (!errorMessages.isEmpty()) {
                throw new InvalidPasswordException(errorMessages);
            }
        }
    }

    public org.passay.PasswordValidator getPasswordValidator(PasswordPolicy policy) {
        List<Rule> rules = new ArrayList<>();
        if (policy.getMinLength()>=0 && policy.getMaxLength()>0) {
            rules.add(new LengthRule(policy.getMinLength(), policy.getMaxLength()));
        }
        if (policy.getRequireUpperCaseCharacter()>0) {
            rules.add(new UppercaseCharacterRule(policy.getRequireUpperCaseCharacter()));
        }
        if (policy.getRequireLowerCaseCharacter()>0) {
            rules.add(new LowercaseCharacterRule(policy.getRequireLowerCaseCharacter()));
        }
        if (policy.getRequireDigit()>0) {
            rules.add(new DigitCharacterRule(policy.getRequireDigit()));
        }
        if (policy.getRequireSpecialCharacter() > 0) {
            rules.add(new SpecialCharacterRule(policy.getRequireSpecialCharacter()));
        }
        return new org.passay.PasswordValidator(rules);
    }
}
