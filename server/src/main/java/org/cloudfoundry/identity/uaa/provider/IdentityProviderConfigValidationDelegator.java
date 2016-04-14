package org.cloudfoundry.identity.uaa.provider;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;

public class IdentityProviderConfigValidationDelegator {
    private Map<String, IdentityProviderConfigValidator> delegates;

    public void validate(AbstractIdentityProviderDefinition definition, String type) {
        if (type.equals(OAUTH20) || type.equals(OIDC10)) {
            delegates.get("xoauth").validate(definition);
        } else if(type.equals(UAA)) {
            delegates.get(UAA).validate(definition);
        }
    }

    public void setDelegates(Map<String, IdentityProviderConfigValidator> delegates) {
        this.delegates = delegates;
    }
}
