package org.cloudfoundry.identity.uaa.zone;


import static org.cloudfoundry.identity.uaa.util.PasswordValidatorUtil.*;

import org.passay.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;



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

    private static PropertiesMessageResolver messageResolver;

    static {
        messageResolver = messageResolver(DEFAULT_MESSAGE_PATH);
    }
    private final ClientSecretPolicy globalDefaultClientSecretPolicy;

    public ZoneAwareClientSecretPolicyValidator(ClientSecretPolicy globalDefaultClientSecretPolicy) {
        this.globalDefaultClientSecretPolicy = globalDefaultClientSecretPolicy;
    }

    @Override
    public void validate(String clientSecret) throws InvalidClientSecretException {
        if(clientSecret == null) {
            throw new InvalidClientSecretException("Client Secret cannot be null");
        }

        ClientSecretPolicy clientSecretPolicy = this.globalDefaultClientSecretPolicy;

        IdentityZone zone = IdentityZoneHolder.get();
        if(zone.getConfig().getClientSecretPolicy().getMinLength() != -1) {
            clientSecretPolicy = zone.getConfig().getClientSecretPolicy();
        }

        PasswordValidator clientSecretValidator = validator(clientSecretPolicy,
                                                        messageResolver);
        RuleResult result = clientSecretValidator.validate(new PasswordData(clientSecret));
        if (!result.isValid()) {
            List<String> errorMessages = new LinkedList<>();
            for (String s : clientSecretValidator.getMessages(result)) {
                errorMessages.add(s);
            }
            if (!errorMessages.isEmpty()) {
                throw new InvalidClientSecretException(errorMessages);
            }
        }
    }
}
