/**
 * ****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
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

package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.authentication.GenericPasswordPolicy;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.MessageResolver;
import org.passay.PasswordValidator;
import org.passay.PropertiesMessageResolver;
import org.passay.Rule;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;


public final class PasswordValidatorUtil {

    private PasswordValidatorUtil() {
    }

    public static PropertiesMessageResolver messageResolver(String messagesResourcePath) {
        final Properties props = new Properties();
        try (InputStream in = PasswordValidatorUtil.class.getResourceAsStream(messagesResourcePath)) {
            props.load(in);
            return new PropertiesMessageResolver(props);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Error loading default message properties.",
                    e);
        }
    }


    public static PasswordValidator validator(GenericPasswordPolicy<?> policy,
            MessageResolver messageResolver) {
        List<Rule> rules = new ArrayList<>();

        //length is always a rule. We do not allow blank password
        int minLength = Math.max(1, policy.getMinLength());
        int maxLength = policy.getMaxLength() > 0 ? policy.getMaxLength() : Integer.MAX_VALUE;
        rules.add(new LengthRule(minLength, maxLength));

        if (policy.getRequireUpperCaseCharacter() > 0) {
            rules.add(new CharacterRule(EnglishCharacterData.UpperCase, policy.getRequireUpperCaseCharacter()));
        }
        if (policy.getRequireLowerCaseCharacter() > 0) {
            rules.add(new CharacterRule(EnglishCharacterData.LowerCase, policy.getRequireLowerCaseCharacter()));
        }
        if (policy.getRequireDigit() > 0) {
            rules.add(new CharacterRule(EnglishCharacterData.Digit, policy.getRequireDigit()));
        }
        if (policy.getRequireSpecialCharacter() > 0) {
            rules.add(new CharacterRule(EnglishCharacterData.Special, policy.getRequireSpecialCharacter()));
        }
        return new PasswordValidator(messageResolver, rules);
    }
}
