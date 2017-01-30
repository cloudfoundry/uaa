package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.util.StringUtils.hasText;

public class XOAuthIdentityProviderConfigValidator implements IdentityProviderConfigValidator {

    public void validate(AbstractIdentityProviderDefinition definition) {
        AbstractXOAuthIdentityProviderDefinition def = (AbstractXOAuthIdentityProviderDefinition) definition;
        if (def == null) {
            throw new IllegalArgumentException("Config cannot be null for OAUTH2.0/OIDC1.0 provider");
        }

        List<String> errors = new ArrayList<>();
        if (def instanceof OIDCIdentityProviderDefinition && ((OIDCIdentityProviderDefinition)definition).getDiscoveryUrl() != null) {
            //we don't require auth/token url or keys/key url
        } else {
            if (def.getAuthUrl() == null) {
                errors.add("Authorization URL must be a valid URL");
            }

            if (def.getTokenUrl() == null) {
                errors.add("Token URL must be a valid URL");
            }

            if(!hasText(def.getTokenKey()) && def.getTokenKeyUrl() == null) {
                errors.add("Either token key or token key URL must be specified");
            }
        }

        if(!hasText(def.getRelyingPartyId())) {
            errors.add("Relying Party Id must be the client-id for the UAA that is registered with the external IDP");
        }

        if(!hasText(def.getRelyingPartySecret()) && !def.getResponseType().contains("token")) {
            errors.add("Relying Party Secret must be the client-secret for the UAA that is registered with the external IDP");
        }

        if(def.isShowLinkText() && !hasText(def.getLinkText())) {
            errors.add("Link Text must be specified because showLinkText is true");
        }


        if(!errors.isEmpty()) {
            String errorMessages = errors.stream().collect(Collectors.joining(","));
            throw new IllegalArgumentException("Invalid config for Identity Provider " + errorMessages);
        }
    }
}
