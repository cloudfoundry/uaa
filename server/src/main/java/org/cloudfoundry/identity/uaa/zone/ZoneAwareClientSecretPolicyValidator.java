package org.cloudfoundry.identity.uaa.zone;

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

    private final ClientSecretPolicy globalDefaultClientSecretPolicy;

    public ZoneAwareClientSecretPolicyValidator(ClientSecretPolicy globalDefaultClientSecretPolicy) {
        this.globalDefaultClientSecretPolicy = globalDefaultClientSecretPolicy;
    }

    @Override
    public void validate(String clientSecret) throws InvalidClientSecretException {

    }
}
