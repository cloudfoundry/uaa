package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.BaseIdentityProviderValidator;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.springframework.util.StringUtils.hasText;

@Component
public class ExternalOAuthIdentityProviderConfigValidator extends BaseIdentityProviderValidator {

    private static final Set<String> oAuthStandardParameters = Set.of("redirect_uri", "code", "client_id", "client_secret", "response_type",
        "grant_type", "code_verifier", "client_assertion", "client_assertion_type", "code_challenge", "code_challenge_method", "nonce", "state",
        "scope", "assertion", "subject_token", "actor_token", "username", "password");

    @Override
    public void validate(AbstractIdentityProviderDefinition definition) {
        if (definition == null) {
            throw new IllegalArgumentException("Config cannot be null OAUTH2.0/OIDC1.0 provider");
        }
        if (!(definition instanceof AbstractExternalOAuthIdentityProviderDefinition)) {
            throw new IllegalArgumentException("Config is of wrong type for OAUTH2.0/OIDC1.0 provider:" + definition.getClass().getName());
        }

        AbstractExternalOAuthIdentityProviderDefinition def = (AbstractExternalOAuthIdentityProviderDefinition) definition;

        List<String> errors = new ArrayList<>();
        if (def instanceof OIDCIdentityProviderDefinition) {
            OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = (OIDCIdentityProviderDefinition) def;
            if (oidcIdentityProviderDefinition.getDiscoveryUrl() != null) {
                //we don't require auth/token url or keys/key url
            } else {
                if (def.getAuthUrl() == null) {
                    errors.add("Authorization URL must be a valid URL");
                }

                if (def.getTokenUrl() == null) {
                    errors.add("Token URL must be a valid URL");
                }

                if (!hasText(def.getTokenKey()) && def.getTokenKeyUrl() == null) {
                    errors.add("Either token key or token key URL must be specified");
                }
            }

            if (Optional.ofNullable(oidcIdentityProviderDefinition.getAdditionalAuthzParameters()).orElse(Collections.emptyMap())
                .keySet().stream().anyMatch(ExternalOAuthIdentityProviderConfigValidator::isOAuthStandardParameter)) {
                errors.add("No OAuth standard parameters allowed in section additionalAuthzParameters");
            }
        }

        if (!hasText(def.getRelyingPartyId())) {
            errors.add("Relying Party Id must be the client-id for the UAA that is registered with the external IDP");
        }

        if (def.isShowLinkText() && !hasText(def.getLinkText())) {
            errors.add("Link Text must be specified because showLinkText is true");
        }


        if (!errors.isEmpty()) {
            String errorMessages = String.join(",", errors);
            throw new IllegalArgumentException("Invalid config for Identity Provider " + errorMessages);
        }
    }

    protected static boolean isOAuthStandardParameter(String value) {
        return oAuthStandardParameters.contains(value);
    }
}
