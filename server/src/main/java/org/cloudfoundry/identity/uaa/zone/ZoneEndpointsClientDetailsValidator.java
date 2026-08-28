package org.cloudfoundry.identity.uaa.zone;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.AuthorityUtils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.client.ClientAdminEndpointsValidator.checkMtlsClientConfigAllowed;
import static org.cloudfoundry.identity.uaa.client.ClientAdminEndpointsValidator.checkRequestedGrantTypes;
import static org.cloudfoundry.identity.uaa.client.ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;

@Component("zoneEndpointsClientDetailsValidator")
public class ZoneEndpointsClientDetailsValidator implements ClientDetailsValidator {

    private static final String REQUIRED_SCOPE = "zones.write";
    private final ClientSecretValidator clientSecretValidator;
    private final boolean mtlsEnabled;

    public ZoneEndpointsClientDetailsValidator(
            final ClientSecretValidator clientSecretValidator,
            @Value("${uaa.mtls-enabled:false}") final boolean mtlsEnabled) {
        this.clientSecretValidator = clientSecretValidator;
        this.mtlsEnabled = mtlsEnabled;
    }

    @Override
    public ClientDetails validate(ClientDetails clientDetails, Mode mode) throws InvalidClientDetailsException {

        if (mode == Mode.CREATE) {
            Map<String, Object> additionalInformation = clientDetails.getAdditionalInformation();
            if (additionalInformation == null) {
                additionalInformation = Collections.emptyMap();
            }
            if (!Collections.singleton("openid").equals(clientDetails.getScope())) {
                throw new InvalidClientDetailsException("only openid scope is allowed");
            }
            if (!Collections.singleton("uaa.resource").equals(AuthorityUtils.authorityListToSet(clientDetails.getAuthorities()))) {
                throw new InvalidClientDetailsException("only uaa.resource authority is allowed");
            }
            if (StringUtils.isBlank(clientDetails.getClientId())) {
                throw new InvalidClientDetailsException("client_id cannot be blank");
            }
            checkRequestedGrantTypes(clientDetails.getAuthorizedGrantTypes());
            checkMtlsClientConfigAllowed(additionalInformation, mtlsEnabled, clientDetails.getClientId());
            validateTlsClientAuthClaimConfig(additionalInformation, clientDetails.getClientId());
            validateTlsClientAuthClaimConfig(getNestedTlsClientAuthClaimConfig(additionalInformation), clientDetails.getClientId());
            boolean hasTlsClientAuthCa = hasNonblankTlsClientAuthCa(additionalInformation);
            if (clientDetails.getAuthorizedGrantTypes().contains(GRANT_TYPE_CLIENT_CREDENTIALS) ||
                    clientDetails.getAuthorizedGrantTypes().contains(GRANT_TYPE_AUTHORIZATION_CODE) ||
                    clientDetails.getAuthorizedGrantTypes().contains(GRANT_TYPE_USER_TOKEN) ||
                    clientDetails.getAuthorizedGrantTypes().contains(GRANT_TYPE_REFRESH_TOKEN) ||
                    clientDetails.getAuthorizedGrantTypes().contains(GRANT_TYPE_SAML2_BEARER) ||
                    clientDetails.getAuthorizedGrantTypes().contains(GRANT_TYPE_JWT_BEARER) ||
                    clientDetails.getAuthorizedGrantTypes().contains(GRANT_TYPE_TOKEN_EXCHANGE) ||
                    clientDetails.getAuthorizedGrantTypes().contains(GRANT_TYPE_PASSWORD)) {
                if (!hasTlsClientAuthCa && StringUtils.isBlank(clientDetails.getClientSecret())) {
                    throw new InvalidClientDetailsException("client_secret cannot be blank");
                }
                clientSecretValidator.validate(clientDetails.getClientSecret());
            }
            if (!Collections.singletonList(OriginKeys.UAA).equals(additionalInformation.get(ClientConstants.ALLOWED_PROVIDERS))) {
                throw new InvalidClientDetailsException("only the internal IdP ('uaa') is allowed");
            }

            UaaClientDetails validatedClientDetails = new UaaClientDetails(clientDetails);
            validatedClientDetails.setAdditionalInformation(clientDetails.getAdditionalInformation());
            validatedClientDetails.setResourceIds(Collections.singleton("none"));
            validatedClientDetails.addAdditionalInformation(ClientConstants.CREATED_WITH, REQUIRED_SCOPE);
            return validatedClientDetails;
        } else if (mode == Mode.MODIFY) {
            throw new IllegalStateException("This validator cannot be used for modification requests");
        } else if (mode == Mode.DELETE) {
            if (!REQUIRED_SCOPE.equals(clientDetails.getAdditionalInformation().get(ClientConstants.CREATED_WITH))) {
                throw new InvalidClientDetailsException("client must have been " + ClientConstants.CREATED_WITH + " scope " + REQUIRED_SCOPE);
            }
            return clientDetails;
        }
        throw new IllegalStateException("This validator must be called with a mode");
    }

    static boolean hasNonblankTlsClientAuthCa(Map<String, Object> additionalInformation) {
        if (additionalInformation == null) {
            return false;
        }

        Object rawConfig = additionalInformation.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
        if (rawConfig instanceof String pem) {
            return !pem.isBlank();
        }
        if (rawConfig instanceof TlsClientAuthConfiguration config) {
            return TlsClientAuthConfiguration.isConfigured(config);
        }
        if (rawConfig instanceof Map<?, ?> config) {
            if (!(config.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA) instanceof String pem) || pem.isBlank()) {
                return false;
            }
            try {
                return TlsClientAuthConfiguration.isConfigured(
                        JsonUtils.convertValue(rawConfig, TlsClientAuthConfiguration.class));
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }

    private static Map<String, Object> getNestedTlsClientAuthClaimConfig(Map<String, Object> additionalInformation) {
        Object rawConfig = additionalInformation.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
        Map<String, Object> nestedConfig = new HashMap<>();
        if (rawConfig instanceof TlsClientAuthConfiguration config) {
            if (config.getClaimMappings() != null) {
                nestedConfig.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, config.getClaimMappings());
            }
            if (config.getSubTemplate() != null) {
                nestedConfig.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, config.getSubTemplate());
            }
            if (config.getAudTemplates() != null) {
                nestedConfig.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES, config.getAudTemplates());
            }
            if (config.getRequiredClaims() != null) {
                nestedConfig.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, config.getRequiredClaims());
            }
        } else if (rawConfig instanceof Map<?, ?> config) {
            config.forEach((key, value) -> {
                if (key instanceof String name) {
                    nestedConfig.put(name, value);
                }
            });
        }
        if ((nestedConfig.containsKey(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE)
                || nestedConfig.containsKey(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES)
                || nestedConfig.containsKey(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS))
                && (!nestedConfig.containsKey(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS)
                || nestedConfig.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS) == null)) {
            nestedConfig.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, Collections.emptyList());
        }
        return nestedConfig;
    }

    @Override
    public ClientSecretValidator getClientSecretValidator() {
        return this.clientSecretValidator;
    }
}
