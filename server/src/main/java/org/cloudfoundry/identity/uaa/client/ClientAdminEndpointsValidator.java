/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsCreation;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.authority.AuthorityUtils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;

public class ClientAdminEndpointsValidator implements InitializingBean, ClientDetailsValidator {


    private final Logger logger = LoggerFactory.getLogger(getClass());

    public static final Set<String> VALID_GRANTS =
            new HashSet<>(
                    Arrays.asList(
                            GRANT_TYPE_IMPLICIT,
                            GRANT_TYPE_PASSWORD,
                            GRANT_TYPE_CLIENT_CREDENTIALS,
                            GRANT_TYPE_AUTHORIZATION_CODE,
                            GRANT_TYPE_REFRESH_TOKEN,
                            GRANT_TYPE_USER_TOKEN,
                            GRANT_TYPE_SAML2_BEARER,
                            GRANT_TYPE_JWT_BEARER,
                            GRANT_TYPE_TOKEN_EXCHANGE
                    )
            );

    private static final Collection<String> NON_ADMIN_INVALID_GRANTS = new HashSet<>(Collections.singletonList(
            "password"));

    private static final Collection<String> NON_ADMIN_VALID_AUTHORITIES = new HashSet<>(Collections.singletonList(
            "uaa.none"));

    private ClientSecretValidator clientSecretValidator;

    private QueryableResourceManager<ClientDetails> clientDetailsService;

    private final SecurityContextAccessor securityContextAccessor;

    private final IdentityZoneManager identityZoneManager;

    private final Set<String> reservedClientIds = StringUtils.commaDelimitedListToSet(OriginKeys.UAA);

    private final Set<Character> invalidClientIdsCharacters = Set.of('/', '\\');

    public ClientAdminEndpointsValidator(final SecurityContextAccessor securityContextAccessor,
                                         final IdentityZoneManager identityZoneManager) {
        this.securityContextAccessor = securityContextAccessor;
        this.identityZoneManager = identityZoneManager;
    }

    /**
     * @param clientDetailsService the clientDetailsService to set
     */
    public void setClientDetailsService(QueryableResourceManager<ClientDetails> clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.state(clientDetailsService != null, "A ClientDetailsService must be provided");
    }

    /* (non-Javadoc)
         * @see org.cloudfoundry.identity.uaa.oauth.ClientDetailsValidatorInterface#validate(org.springframework.security.oauth2.provider.ClientDetails, boolean)
         */
    @Override
    public ClientDetails validate(ClientDetails prototype, Mode mode) {
        return validate(prototype, mode == Mode.CREATE, true);
    }

    public ClientDetails validate(ClientDetails prototype, boolean create, boolean checkAdmin) throws InvalidClientDetailsException {

        UaaClientDetails client = new UaaClientDetails(prototype);
        if (prototype instanceof UaaClientDetails details) {
            Set<String> scopes = details.getAutoApproveScopes();
            if (scopes != null) {
                client.setAutoApproveScopes(details.getAutoApproveScopes());
            }
        }

        client.setAdditionalInformation(prototype.getAdditionalInformation());
        String clientId = client.getClientId();
        if (create) {
            if (reservedClientIds.contains(clientId)) {
                throw new InvalidClientDetailsException("Not allowed: " + clientId + " is a reserved client_id");
            }
            if (invalidClientIdsCharacters.stream().anyMatch(c -> clientId.indexOf(c) > -1)) {
                throw new InvalidClientDetailsException("Not allowed characters: " + clientId + " must not contain any of " + invalidClientIdsCharacters);
            }
        }

        validateClientRedirectUri(client);

        Set<String> requestedGrantTypes = client.getAuthorizedGrantTypes();
        if (requestedGrantTypes.isEmpty()) {
            throw new InvalidClientDetailsException("An authorized grant type must be provided. Must be one of: "
                    + VALID_GRANTS.toString());
        }
        checkRequestedGrantTypes(requestedGrantTypes);

        if ((requestedGrantTypes.contains(GRANT_TYPE_AUTHORIZATION_CODE) || requestedGrantTypes.contains(GRANT_TYPE_PASSWORD))
                && !requestedGrantTypes.contains(GRANT_TYPE_REFRESH_TOKEN)) {
            logger.debug("requested grant type missing refresh_token: {}", clientId);

            requestedGrantTypes.add(GRANT_TYPE_REFRESH_TOKEN);
        }

        if (requestedGrantTypes.contains(GRANT_TYPE_JWT_BEARER) && (client.getScope() == null || client.getScope().isEmpty())) {
            logger.debug("Invalid client: {}. Scope cannot be empty for grant_type {}", clientId, GRANT_TYPE_JWT_BEARER);
            throw new InvalidClientDetailsException("Scope cannot be empty for grant_type " + GRANT_TYPE_JWT_BEARER);
        }

        if (requestedGrantTypes.contains(GRANT_TYPE_TOKEN_EXCHANGE)) {
            if (
                    (requestedGrantTypes.contains(GRANT_TYPE_REFRESH_TOKEN) && requestedGrantTypes.size()>2) ||
                    (!requestedGrantTypes.contains(GRANT_TYPE_REFRESH_TOKEN) && requestedGrantTypes.size()>1)
            ) {
                throw new InvalidClientDetailsException(
                        GRANT_TYPE_TOKEN_EXCHANGE +
                                " is a privileged grant_type, and cannot be used in conjunction with other grant types."
                );
            }
        }

        if (checkAdmin &&
                !(securityContextAccessor.isAdmin() || securityContextAccessor.getScopes().contains("clients.admin"))
        ) {

            // Not admin, so be strict with grant types and scopes
            for (String grant : requestedGrantTypes) {
                if (NON_ADMIN_INVALID_GRANTS.contains(grant)) {
                    throw new InvalidClientDetailsException(grant
                            + " is not an allowed grant type for non-admin caller.");
                }
            }

            if (requestedGrantTypes.contains(GRANT_TYPE_IMPLICIT)
                    && requestedGrantTypes.contains(GRANT_TYPE_AUTHORIZATION_CODE)) {
                throw new InvalidClientDetailsException(
                        "Not allowed: implicit grant type is not allowed together with authorization_code");
            }

            String callerId = securityContextAccessor.getClientId();
            ClientDetails caller = null;
            try {
                caller = clientDetailsService.retrieve(callerId, identityZoneManager.getCurrentIdentityZoneId());
            } catch (Exception e) {
                // best effort to get the caller, but the caller might not belong to this zone.
            }
            if (callerId != null && caller != null) {

                // New scopes are allowed if they are for the caller or the new
                // client.
                String callerPrefix = callerId + ".";


                Set<String> validScope = caller.getScope();
                for (String scope : client.getScope()) {
                    if (scope.startsWith(callerPrefix)) {
                        // Allowed
                        continue;
                    }
                    if (!validScope.contains(scope)) {
                        throw new InvalidClientDetailsException(scope + " is not an allowed scope for caller="
                                + callerId + ". Must have prefix in [" + callerPrefix + "] or be one of: "
                                + validScope.toString());
                    }
                }

            } else {
                if (!client.getScope().isEmpty()) {
                    throw new InvalidClientDetailsException("No scopes alllowed for null caller and client_id=" + clientId + ".");
                }
            }

            Set<String> validAuthorities = new HashSet<>(NON_ADMIN_VALID_AUTHORITIES);
            if (requestedGrantTypes.contains(GRANT_TYPE_CLIENT_CREDENTIALS)) {
                // If client_credentials is used then the client might be a
                // resource server
                validAuthorities.add("uaa.resource");
            }

            for (String authority : AuthorityUtils.authorityListToSet(client.getAuthorities())) {
                if (!validAuthorities.contains(authority)) {
                    throw new InvalidClientDetailsException(authority + " is not an allowed authority for caller="
                            + callerId + ". Must be one of: " + validAuthorities.toString());
                }
            }

        }

        if (client.getAuthorities().isEmpty()) {
            client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        }

        // The UAA does not allow or require resource ids to be registered
        // because they are determined dynamically
        client.setResourceIds(Collections.singleton("none"));

        if (client.getScope().isEmpty()) {
            client.setScope(Collections.singleton("uaa.none"));
        }

        if (requestedGrantTypes.contains(GRANT_TYPE_IMPLICIT) && StringUtils.hasText(client.getClientSecret())) {
            throw new InvalidClientDetailsException("Implicit grant should not have a client_secret");
        }
        if (create) {
            clientSecretValidator.validate(client.getClientSecret());

            if (prototype instanceof ClientDetailsCreation clientDetailsCreation) {
                if (StringUtils.hasText(clientDetailsCreation.getJsonWebKeyUri()) || StringUtils.hasText(clientDetailsCreation.getJsonWebKeySet())) {
                    ClientJwtConfiguration clientJwtConfiguration = ClientJwtConfiguration.parse(clientDetailsCreation.getJsonWebKeyUri(),
                            clientDetailsCreation.getJsonWebKeySet());
                    if (clientJwtConfiguration != null) {
                        clientJwtConfiguration.writeValue(client);
                    } else {
                        throw new InvalidClientDetailsException(
                                "Client with client jwt configuration not valid");
                    }
                }
            }
        }

        return client;

    }

    public void validateClientRedirectUri(ClientDetails client) {
        Set<String> uris = client.getRegisteredRedirectUri();

        for (String grantType : Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT)) {
            if (client.getAuthorizedGrantTypes().contains(grantType)) {

                if (isMissingRedirectUris(uris)) {
                    throw new InvalidClientDetailsException(grantType + " grant type requires at least one redirect URL.");
                }

                for (String uri : uris) {
                    if (!UaaUrlUtils.isValidRegisteredRedirectUrl(uri) || uri.contains(",")) {
                        throw new InvalidClientDetailsException(
                                "One of the redirect_uri is invalid: %s".formatted(uri));
                    }
                }
            }
        }
    }

    private boolean isMissingRedirectUris(Set<String> uris) {
        return uris == null || uris.isEmpty();
    }

    public static void checkRequestedGrantTypes(Set<String> requestedGrantTypes) {
        for (String grant : requestedGrantTypes) {
            if (!VALID_GRANTS.contains(grant)) {
                throw new InvalidClientDetailsException(grant + " is not an allowed grant type. Must be one of: "
                        + VALID_GRANTS.toString());
            }
        }
    }

    @Override
    public ClientSecretValidator getClientSecretValidator() {
        return this.clientSecretValidator;
    }

    public void setClientSecretValidator(ClientSecretValidator clientSecretValidator) {
        this.clientSecretValidator = clientSecretValidator;
    }
}
