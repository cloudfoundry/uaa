package org.cloudfoundry.identity.uaa.zone;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.isEmpty;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.isUrl;
import static org.springframework.util.StringUtils.hasText;

public class ConsentValidator {
    public static void validate(Consent consent)  throws InvalidIdentityZoneConfigurationException {
        if (consent != null) {
            if (isEmpty(consent.getText())) {
                throw new InvalidIdentityZoneConfigurationException("Consent text must be set if configuring consent");
            }
            if (hasText(consent.getLink())) {
                if (!isUrl(consent.getLink())) {
                    throw new InvalidIdentityZoneConfigurationException("Invalid consent link: " + consent.getLink() + ". Must be a properly formatted URI beginning with http:// or https://", null);
                }
            }
        }

    }
}
