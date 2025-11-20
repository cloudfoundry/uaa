package org.cloudfoundry.identity.uaa.provider;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.util.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component("keyProviderValidator")
public class KeyProviderValidator {

    @Autowired
    ClientDetailsService clientDetailsService;

    public void validate(KeyProviderConfig config) throws KeyProviderValidatorException {
        if(!StringUtils.hasText(config.getClientId())) {
            throw new KeyProviderValidatorException("Empty client id.");
        }
        if(!StringUtils.hasText(config.getDcsTenantId())){
            throw new KeyProviderValidatorException("Empty tenant id.");
        }
        try {
            ClientDetails retrieved = clientDetailsService.loadClientByClientId(config.getClientId());
        } catch (NoSuchClientException e) {
            throw new KeyProviderValidatorException("Client " + config.getClientId() + " was not found.", e);
        }
    }

    public ClientDetailsService getClientDetailsService() {
        return clientDetailsService;
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public class KeyProviderValidatorException extends Exception {
        public KeyProviderValidatorException(String message) {
            super(message);
        }

        public KeyProviderValidatorException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
