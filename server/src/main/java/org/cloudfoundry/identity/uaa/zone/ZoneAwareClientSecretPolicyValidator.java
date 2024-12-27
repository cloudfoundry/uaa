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
package org.cloudfoundry.identity.uaa.zone;

import org.passay.PasswordData;
import org.passay.PasswordValidator;
import org.passay.PropertiesMessageResolver;
import org.passay.RuleResult;
import org.springframework.util.StringUtils;

import java.util.LinkedList;
import java.util.List;

import static org.cloudfoundry.identity.uaa.util.PasswordValidatorUtil.messageResolver;
import static org.cloudfoundry.identity.uaa.util.PasswordValidatorUtil.validator;


/**
 *
 * <p>
 *      Requirements
 *      config.clientSecretPolicy.minLength    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Minimum number of characters required for secret to be considered valid (defaults to 0).
 *      config.clientSecretPolicy.maxLength    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Maximum number of characters required for secret to be considered valid (defaults to 255).
 *      config.clientSecretPolicy.requireUpperCaseCharacter    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Minimum number of uppercase characters required for secret to be considered valid (defaults to 0).
 *      config.clientSecretPolicy.requireLowerCaseCharacter    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Minimum number of lowercase characters required for secret to be considered valid (defaults to 0).
 *      config.clientSecretPolicy.requireDigit    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Minimum number of digits required for secret to be considered valid (defaults to 0).
 *      config.clientSecretPolicy.requireSpecialCharacter    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Minimum number of special characters required for secret to be considered valid (defaults to 0).
 *      config.clientSecretPolicy.expiresecretInMonths    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Number of months after which current secret expires (defaults to 0).
 *
 */
public class ZoneAwareClientSecretPolicyValidator implements ClientSecretValidator {

    public static final String DEFAULT_MESSAGE_PATH = "/clientsecret-messages.properties";

    private static final PropertiesMessageResolver messageResolver;

    static {
        messageResolver = messageResolver(DEFAULT_MESSAGE_PATH);
    }

    private final ClientSecretPolicy globalDefaultClientSecretPolicy;

    public ZoneAwareClientSecretPolicyValidator(ClientSecretPolicy globalDefaultClientSecretPolicy) {
        this.globalDefaultClientSecretPolicy = globalDefaultClientSecretPolicy;
    }

    @Override
    public void validate(String clientSecret) throws InvalidClientSecretException {
        if (!StringUtils.hasText(clientSecret)) {
            return;
        }

        ClientSecretPolicy clientSecretPolicy = this.globalDefaultClientSecretPolicy;

        IdentityZone zone = IdentityZoneHolder.get();
        if (zone.getConfig().getClientSecretPolicy().getMinLength() != -1) {
            clientSecretPolicy = zone.getConfig().getClientSecretPolicy();
        }

        PasswordValidator clientSecretValidator = validator(clientSecretPolicy,
                messageResolver);
        RuleResult result = clientSecretValidator.validate(new PasswordData(clientSecret));
        if (!result.isValid()) {
            List<String> errorMessages = new LinkedList<>(clientSecretValidator.getMessages(result));
            if (!errorMessages.isEmpty()) {
                throw new InvalidClientSecretException(errorMessages);
            }
        }
    }
}
