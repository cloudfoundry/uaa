package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;

import java.util.Map;

public class IdentityProviderConfigValidationDelegator {
    private Map<String, IdentityProviderConfigValidator> delegates;

    public void validate(AbstractIdentityProviderDefinition definition, String type) {
        if (OriginKeys.OAUTH20.equals(type) || OriginKeys.OIDC10.equals(type)) {
            delegates.get("xoauth").validate(definition);
        } else if(OriginKeys.UAA.equals(type)) {
            delegates.get(OriginKeys.UAA).validate(definition);
        }
    }

    public void setDelegates(Map<String, IdentityProviderConfigValidator> delegates) {
        this.delegates = delegates;
    }
}
