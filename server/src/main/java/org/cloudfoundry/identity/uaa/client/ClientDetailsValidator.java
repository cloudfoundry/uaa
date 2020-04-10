

package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.springframework.security.oauth2.provider.ClientDetails;

public interface ClientDetailsValidator {

    /**
     *
     * @return Returns the configured client secret validator
     */
    ClientSecretValidator getClientSecretValidator();

    /**
     *
     * @param clientDetails
     * @param mode represents the request {@link Mode}
     * @return A validated and possibly modified client
     */
    ClientDetails validate(ClientDetails clientDetails, Mode mode) throws InvalidClientDetailsException;

    enum Mode {
        CREATE, MODIFY, DELETE
    }

}