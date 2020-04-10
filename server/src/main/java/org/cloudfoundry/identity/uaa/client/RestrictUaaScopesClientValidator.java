package org.cloudfoundry.identity.uaa.client;


import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;

public class RestrictUaaScopesClientValidator implements ClientDetailsValidator {
    private final UaaScopes uaaScopes;

    public RestrictUaaScopesClientValidator(UaaScopes uaaScopes) {
        this.uaaScopes = uaaScopes;
    }

    public UaaScopes getUaaScopes() {
        return uaaScopes;
    }

    @Override
    public ClientSecretValidator getClientSecretValidator() {
        return null;
    }

    @Override
    public ClientDetails validate(ClientDetails clientDetails, Mode mode) throws InvalidClientDetailsException {
        if (Mode.CREATE.equals(mode) || Mode.MODIFY.equals(mode)) {
            for (String scope : clientDetails.getScope()) {
                if (uaaScopes.isUaaScope(scope)) {
                    throw new InvalidClientDetailsException(scope+" is a restricted scope.");
                }
            }
            for (GrantedAuthority authority : clientDetails.getAuthorities()) {
                if (uaaScopes.isUaaScope(authority)) {
                    throw new InvalidClientDetailsException(authority.getAuthority()+" is a restricted authority.");
                }
            }
        }
        return clientDetails;
    }
}
