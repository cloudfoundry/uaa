/*******************************************************************************
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
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
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;

public class ClientAdminEndpointsValidator implements InitializingBean, ClientDetailsValidator {


    private final Log logger = LogFactory.getLog(getClass());

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
                        GRANT_TYPE_JWT_BEARER
                )
        );

    private static final Collection<String> NON_ADMIN_INVALID_GRANTS = new HashSet<>(Arrays.asList("password"));

    private static final Collection<String> NON_ADMIN_VALID_AUTHORITIES = new HashSet<>(Arrays.asList("uaa.none"));

    private ClientSecretValidator clientSecretValidator;

    private QueryableResourceManager<ClientDetails> clientDetailsService;

    private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();


    private Set<String> reservedClientIds = StringUtils.commaDelimitedListToSet(OriginKeys.UAA);


    /**
     * @param clientDetailsService the clientDetailsService to set
     */
    public void setClientDetailsService(QueryableResourceManager<ClientDetails> clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
        this.securityContextAccessor = securityContextAccessor;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
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

        BaseClientDetails client = new BaseClientDetails(prototype);
        if (prototype instanceof BaseClientDetails) {
            Set<String> scopes = ((BaseClientDetails)prototype).getAutoApproveScopes();
            if (scopes!=null) {
                client.setAutoApproveScopes(((BaseClientDetails) prototype).getAutoApproveScopes());
            }
        }

        client.setAdditionalInformation(prototype.getAdditionalInformation());
        String clientId = client.getClientId();
        if (create && reservedClientIds.contains(clientId)) {
            throw new InvalidClientDetailsException("Not allowed: " + clientId + " is a reserved client_id");
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
            logger.debug("requested grant type missing refresh_token: " + clientId);

            requestedGrantTypes.add(GRANT_TYPE_REFRESH_TOKEN);
        }

        if(requestedGrantTypes.contains(GRANT_TYPE_JWT_BEARER)) {
            if(client.getScope() == null || client.getScope().isEmpty()) {
                logger.debug("Invalid client: " + clientId + ". Scope cannot be empty for grant_type " + GRANT_TYPE_JWT_BEARER);
                throw new InvalidClientDetailsException("Scope cannot be empty for grant_type " + GRANT_TYPE_JWT_BEARER);
            }
            if(create && !StringUtils.hasText(client.getClientSecret())) {
                logger.debug("Invalid client: " + clientId + ". Client secret is required for grant type " + GRANT_TYPE_JWT_BEARER);
                throw new InvalidClientDetailsException("Client secret is required for grant type " + GRANT_TYPE_JWT_BEARER);
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
                caller = clientDetailsService.retrieve(callerId, IdentityZoneHolder.get().getId());
            } catch (Exception e) {
                // best effort to get the caller, but the caller might not belong to this zone.
            }
            if (callerId != null && caller != null) {

                // New scopes are allowed if they are for the caller or the new
                // client.
                String callerPrefix = callerId + ".";
                String clientPrefix = clientId + ".";


                Set<String> validScope = caller.getScope();
                for (String scope : client.getScope()) {
                    if (scope.startsWith(callerPrefix) || scope.startsWith(clientPrefix)) {
                        // Allowed
                        continue;
                    }
                    if (!validScope.contains(scope)) {
                        throw new InvalidClientDetailsException(scope + " is not an allowed scope for caller="
                                        + callerId + ". Must have prefix in [" + callerPrefix + "," + clientPrefix
                                        + "] or be one of: " + validScope.toString());
                    }
                }

            }
            else {
                // New scopes are allowed if they are for the caller or the new
                // client.
                String clientPrefix = clientId + ".";

                for (String scope : client.getScope()) {
                    if (!scope.startsWith(clientPrefix)) {
                        throw new InvalidClientDetailsException(scope
                                        + " is not an allowed scope for null caller and client_id=" + clientId
                                        + ". Must start with '" + clientPrefix + "'");
                    }
                }
            }

            Set<String> validAuthorities = new HashSet<String>(NON_ADMIN_VALID_AUTHORITIES);
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

        if (requestedGrantTypes.contains(GRANT_TYPE_IMPLICIT)) {
            if (StringUtils.hasText(client.getClientSecret())) {
                throw new InvalidClientDetailsException("Implicit grant should not have a client_secret");
            }
        }
        if (create) {
            // Only check for missing secret if client is being created.
            if (requestedGrantTypes.contains(GRANT_TYPE_CLIENT_CREDENTIALS)
                    || requestedGrantTypes.contains(GRANT_TYPE_AUTHORIZATION_CODE)) {
                if(!StringUtils.hasText(client.getClientSecret())) {
                    logger.debug("Client secret is required for client_credentials and authorization_code grant types");
                    throw new InvalidClientDetailsException(
                            "Client secret is required for client_credentials and authorization_code grant types");
                }
                clientSecretValidator.validate(client.getClientSecret());
            }
        }

        return client;

    }

    public void validateClientRedirectUri(ClientDetails client) {
        Set<String> uris = client.getRegisteredRedirectUri();

        for(String grant_type: Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT)) {
            if(client.getAuthorizedGrantTypes().contains(grant_type)) {

                if (isMissingRedirectUris(uris)) {
                    throw new InvalidClientDetailsException(grant_type + " grant type requires at least one redirect URL.");
                }

                for (String uri : uris) {
                    if (!UaaUrlUtils.isValidRegisteredRedirectUrl(uri)) {
                        throw new InvalidClientDetailsException(
                            String.format("One of the redirect_uri is invalid: %s", uri));
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
