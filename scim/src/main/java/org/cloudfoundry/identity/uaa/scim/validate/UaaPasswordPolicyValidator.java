package org.cloudfoundry.identity.uaa.scim.validate;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.config.PasswordPolicy;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.passay.DigitCharacterRule;
import org.passay.LengthRule;
import org.passay.LowercaseCharacterRule;
import org.passay.PasswordData;
import org.passay.PasswordUtils;
import org.passay.Rule;
import org.passay.RuleResult;
import org.passay.SpecialCharacterRule;
import org.passay.UppercaseCharacterRule;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * ****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
public class UaaPasswordPolicyValidator implements PasswordValidator {

    private final IdentityProviderProvisioning provisioning;

    public UaaPasswordPolicyValidator(IdentityProviderProvisioning provisioning) {
        this.provisioning = provisioning;
    }

    @Override
    public Void validate(String password) throws InvalidPasswordException {
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }

        IdentityProvider idp = provisioning.retrieveByOrigin(Origin.UAA, IdentityZoneHolder.get().getId());
        if (idp==null || idp.getConfig()==null) {
            //no config stored
            return null;
        }

        UaaIdentityProviderDefinition idpDefinition = idp.getConfigValue(UaaIdentityProviderDefinition.class);
        if (idpDefinition == null || idpDefinition.getPasswordPolicy() == null) {
            return null;
        }

        PasswordPolicy policy = idpDefinition.getPasswordPolicy();

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
        return null;
    }

    public org.passay.PasswordValidator getPasswordValidator(PasswordPolicy policy) {
        List<Rule> rules = new ArrayList<>();
        if (policy.getMinLength()>0 && policy.getMaxLength()>0) {
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
