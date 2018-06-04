package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.util.StringUtils;

public class ConsentValidator {
    public static void validate(Consent consent)  throws InvalidIdentityZoneConfigurationException {
        if (consent != null) {
            if (StringUtils.isEmpty(consent.getText())) {
                throw new InvalidIdentityZoneConfigurationException("Consent text must be set if configuring consent");
            }
            if (StringUtils.hasText(consent.getLink())) {
                if (!UaaUrlUtils.isUrl(consent.getLink())) {
                    throw new InvalidIdentityZoneConfigurationException("Invalid consent link: " + consent.getLink() + ". Must be a properly formatted URI beginning with http:// or https://", null);
                }
            }
        }

    }
}
