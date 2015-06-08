package org.cloudfoundry.identity.uaa.scim.validate;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.config.PasswordPolicy;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
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

    private final String AT_LEAST_ONE_DIGIT_REGEX = ".*\\d+.*";
    private final String SPECIAL_CHARACTER_REGEX = ".*[^A-Za-z0-9]+.*";

    private final IdentityProviderProvisioning provisioning;

    public UaaPasswordPolicyValidator(IdentityProviderProvisioning provisioning) {
        this.provisioning = provisioning;
    }

    @Override
    public Void validate(String password) throws InvalidPasswordException {
        if (!IdentityZoneHolder.isUaa()) {
            return null;
        }
        IdentityProvider idp = provisioning.retrieveByOrigin(Origin.UAA, IdentityZoneHolder.get().getId());
        Map<String, Object> configMap = JsonUtils.readValue(idp.getConfig(), Map.class);
        PasswordPolicy policy = JsonUtils.convertValue(configMap.get(PasswordPolicy.PASSWORD_POLICY_FIELD), PasswordPolicy.class);
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        List<String> errors = new ArrayList<>();
        if (password.length() < policy.getMinLength()) {
            errors.add("Password must be greater than " + policy.getMinLength() + " characters.");
        }
        if (password.length() > policy.getMaxLength()) {
            errors.add("Password must be shorter than " + policy.getMaxLength() + " characters");
        }
        if (policy.isRequireAtLeastOneLowerCaseCharacter() && password.toUpperCase().equals(password)) {
            errors.add("Password must contain at least one lower case character.");
        }
        if (policy.isRequireAtLeastOneUpperCaseCharacter() && password.toLowerCase().equals(password)) {
            errors.add("Password must contain at least one upper case character.");
        }
        if (policy.isRequireAtLeastOneDigit() && !password.matches(AT_LEAST_ONE_DIGIT_REGEX)) {
            errors.add("Password must contain at least one digit.");
        }
        if (policy.isRequireAtLeastOneSpecialCharacter() && !password.matches(SPECIAL_CHARACTER_REGEX)) {
            errors.add("Password must contain at least one non-alphanumeric character.");
        }
        if (!errors.isEmpty()) {
            throw new InvalidPasswordException(StringUtils.collectionToDelimitedString(errors, ","));
        }

        return null;
    }
}
