package org.cloudfoundry.identity.uaa.scim.validate;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.passay.PasswordData;
import org.passay.PropertiesMessageResolver;
import org.passay.RuleResult;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.LinkedList;
import java.util.List;

import static org.cloudfoundry.identity.uaa.util.PasswordValidatorUtil.messageResolver;
import static org.cloudfoundry.identity.uaa.util.PasswordValidatorUtil.validator;

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
@Component
public class UaaPasswordPolicyValidator implements PasswordValidator {

    private final IdentityProviderProvisioning provisioning;
    private final PasswordPolicy globalDefaultPolicy;

    public static final String DEFAULT_MESSAGE_PATH = "/messages.properties";

    private static final PropertiesMessageResolver messageResolver = messageResolver(DEFAULT_MESSAGE_PATH);

    public UaaPasswordPolicyValidator(
            final @Qualifier("globalPasswordPolicy") PasswordPolicy globalDefaultPolicy,
            final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning
    ) {
        this.globalDefaultPolicy = globalDefaultPolicy;
        this.provisioning = provisioning;
    }

    @Override
    public void validate(String password) throws InvalidPasswordException {
        IdentityProvider<UaaIdentityProviderDefinition> idp = provisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        if (idp == null) {
            //should never happen
            return;
        }

        PasswordPolicy policy = globalDefaultPolicy;

        UaaIdentityProviderDefinition idpDefinition = idp.getConfig();
        if (idpDefinition != null && idpDefinition.getPasswordPolicy() != null) {
            policy = idpDefinition.getPasswordPolicy();
        }

        org.passay.PasswordValidator validator = validator(policy, messageResolver);
        RuleResult result = validator.validate(new PasswordData(password != null ? password : ""));
        if (!result.isValid()) {
            List<String> errorMessages = new LinkedList<>(validator.getMessages(result));
            if (!errorMessages.isEmpty()) {
                throw new InvalidPasswordException(errorMessages);
            }
        }
    }
}
