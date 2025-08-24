package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnauthorizedClientException;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.UaaSecurityContextUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableMap;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.hasText;

/**
 * An {@link OAuth2RequestFactory} that applies various UAA-specific
 * rules to an authorization request,
 * validating it and setting the default values for requested scopes and resource ids.
 *
 *
 */
public class UaaAuthorizationRequestManager implements OAuth2RequestFactory {
    private static final Logger logger = LoggerFactory.getLogger(UaaAuthorizationRequestManager.class);

    private final MultitenantClientServices clientDetailsService;

    private Map<String, String> scopeToResource = Collections.singletonMap("openid", "openid");

    private String scopeSeparator = ".";

    private final SecurityContextAccessor securityContextAccessor;

    private final UaaUserDatabase uaaUserDatabase;

    private final IdentityProviderProvisioning providerProvisioning;
    private final IdentityZoneManager identityZoneManager;

    public UaaAuthorizationRequestManager(final MultitenantClientServices clientDetailsService,
            final SecurityContextAccessor securityContextAccessor,
            final UaaUserDatabase userDatabase,
            final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning providerProvisioning,
            final @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager) {
        this.clientDetailsService = clientDetailsService;
        this.securityContextAccessor = securityContextAccessor;
        this.uaaUserDatabase = userDatabase;
        this.providerProvisioning = providerProvisioning;
        this.identityZoneManager = identityZoneManager;
    }

    /**
     * A map from scope name to resource id, for cases (like openid) that cannot
     * be extracted from the scope name.
     *
     * @param scopeToResource the map to use
     */
    public void setScopesToResources(Map<String, String> scopeToResource) {
        this.scopeToResource = new HashMap<>(scopeToResource);
    }

    /**
     * The string used to separate resource ids from feature names in requested scopes
     * (e.g. "cloud_controller.read").
     *
     * @param scopeSeparator the scope separator to set. Default is period "."
     */
    public void setScopeSeparator(String scopeSeparator) {
        this.scopeSeparator = scopeSeparator;
    }

    /**
     * Create an authorization request applying various UAA rules to the
     * authorizationParameters and the registered
     * client details.
     * <ul>
     * <li>For client_credentials grants, the default requested scopes are the client's
     * granted authorities</li>
     * <li>For other grant types the default requested scopes are the registered requested scopes in
     * the client details</li>
     * <li>Only requested scopes in those lists are valid, otherwise there is an exception
     * </li>
     * <li>If the requested scopes contain separators then resource ids are extracted as
     * the scope value up to the last index of the separator</li>
     * <li>Some requested scopes can be hard-wired to resource ids (like the open id
     * connect values), in which case the separator is ignored</li>
     * </ul>
     *
     */
    public AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters) {

        String clientId = authorizationParameters.get("client_id");
        UaaClientDetails clientDetails = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
        validateParameters(authorizationParameters, clientDetails);
        Set<String> scopes = OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.SCOPE));
        Set<String> responseTypes = OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.RESPONSE_TYPE));
        String state = authorizationParameters.get(OAuth2Utils.STATE);
        String redirectUri = authorizationParameters.get(OAuth2Utils.REDIRECT_URI);
        if (scopes == null || scopes.isEmpty()) {
            // The default for a user token is the requestedScopes registered with the client
            scopes = clientDetails.getScope();
        }

        if (securityContextAccessor.isUser()) {
            String userId = securityContextAccessor.getUserId();
            UaaUser uaaUser = uaaUserDatabase.retrieveUserById(userId);
            Collection<? extends GrantedAuthority> authorities = uaaUser.getAuthorities();
            //validate scopes
            scopes = checkUserScopes(scopes, authorities, clientDetails);
            //check client IDP relationship - allowed providers
            checkClientIdpAuthorization(clientDetails, uaaUser);
        }

        Set<String> resourceIds = getResourceIds(clientDetails, scopes);
        clientDetails.setResourceIds(resourceIds);
        Map<String, String> actualParameters = new HashMap<>(authorizationParameters);
        AuthorizationRequest request = new AuthorizationRequest(
                actualParameters, clientId,
                scopes.isEmpty() ? null : scopes,
                null,
                null,
                false,
                state,
                redirectUri,
                responseTypes
        );
        if (!scopes.isEmpty()) {
            request.setScope(scopes);
        }

        request.setResourceIdsAndAuthoritiesFromClientDetails(clientDetails);

        return request;
    }

    /**
     * Apply UAA rules to validate the requested scopes scope. For client credentials
     * grants the valid requested scopes are actually in
     * the authorities of the client.
     *
     */
    public void validateParameters(Map<String, String> parameters, ClientDetails clientDetails) {
        if (parameters.containsKey("scope")) {
            Set<String> validScope = clientDetails.getScope();
            if (GRANT_TYPE_CLIENT_CREDENTIALS.equals(parameters.get("grant_type"))) {
                validScope = AuthorityUtils.authorityListToSet(clientDetails.getAuthorities());
            }
            Set<Pattern> validWildcards = constructWildcards(validScope);
            Set<String> scopes = OAuth2Utils.parseParameterList(parameters.get("scope"));
            for (String scope : scopes) {
                if (!matches(validWildcards, scope)) {
                    throw new InvalidScopeException(scope + " is invalid. Please use a valid scope name in the request");
                }
            }
        }
    }

    protected void checkClientIdpAuthorization(UaaClientDetails client, UaaUser user) {
        List<String> allowedProviders = (List<String>) client.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS);


        if (allowedProviders == null) {
            //null means any providers - no allowed providers means that we always allow it (backwards compatible)
            return;
        } else if (allowedProviders.isEmpty()) {
            throw new UnauthorizedClientException("Client is not authorized for any identity providers.");
        }

        try {
            IdentityProvider<AbstractIdentityProviderDefinition> provider = providerProvisioning.retrieveByOrigin(user.getOrigin(), user.getZoneId());
            if (provider == null || !allowedProviders.contains(provider.getOriginKey())) {
                throw new DisallowedIdpException("Client is not authorized for specified user's identity provider.");
            }
        } catch (EmptyResultDataAccessException x) {
            //this should not happen...but if it does
            throw new UnauthorizedClientException("User does not belong to a valid identity provider.");
        }
    }

    /**
     * Add or remove requested scopes derived from the current authenticated user's
     * authorities (if any)
     *
     * @param requestedScopes the initial set of requested scopes from the client registration
     * @param clientDetails
     * @param authorities the users authorities
     * @return modified requested scopes adapted according to the rules specified
     */
    @SuppressWarnings("java:S1874")
    private Set<String> checkUserScopes(Set<String> requestedScopes,
            Collection<? extends GrantedAuthority> authorities,
            ClientDetails clientDetails) {
        Set<String> allowed = new LinkedHashSet<>(AuthorityUtils.authorityListToSet(authorities));
        // Add in all default requestedScopes
        Collection<String> defaultScopes = IdentityZoneHolder.get().getConfig().getUserConfig().getDefaultGroups();
        Collection<String> allowedScopes = IdentityZoneHolder.get().getConfig().getUserConfig().resultingAllowedGroups();
        allowed.addAll(defaultScopes);
        if (allowedScopes != null) {
            allowed.retainAll(allowedScopes);
        }

        // Find intersection of user authorities, default requestedScopes and client requestedScopes:
        Set<String> result = intersectScopes(new LinkedHashSet<>(requestedScopes), clientDetails.getScope(), allowed);

        // Check that a token with empty scope is not going to be granted
        if (result.isEmpty() && !clientDetails.getScope().isEmpty()) {
            logger.warn("The requested scopes are invalid");
            throw new InvalidScopeException(requestedScopes + " is invalid. This user is not allowed any of the requested scopes");
        }

        Collection<String> requiredUserGroups = ofNullable((Collection<String>) clientDetails.getAdditionalInformation().get(REQUIRED_USER_GROUPS)).orElse(emptySet());
        if (!UaaTokenUtils.hasRequiredUserAuthorities(requiredUserGroups, authorities)) {
            logger.warn("The requested scopes are invalid");
            throw new InvalidScopeException("User does not meet the client's required group criteria.");
        }

        return result;
    }

    protected Set<String> intersectScopes(Set<String> requestedScopes, Set<String> clientScopes, Set<String> userScopes) {
        Set<String> result = new HashSet<>(userScopes);

        Set<Pattern> clientWildcards = constructWildcards(clientScopes);
        result.removeIf(scope1 -> !matches(clientWildcards, scope1));

        Set<Pattern> requestedWildcards = constructWildcards(requestedScopes);
        result.removeIf(scope -> !matches(requestedWildcards, scope));

        return result;
    }

    protected Set<Pattern> constructWildcards(Set<String> scopes) {
        return UaaStringUtils.constructWildcards(scopes);
    }

    protected boolean matches(Set<Pattern> wildcards, String scope) {
        return UaaStringUtils.matches(wildcards, scope);
    }

    private Set<String> getResourceIds(ClientDetails clientDetails, Set<String> scopes) {
        Set<String> resourceIds = new LinkedHashSet<>();
        //at a minimum - the resourceIds should contain the client this is intended for
        //http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        if (clientDetails.getClientId() != null) {
            resourceIds.add(clientDetails.getClientId());
        }
        for (String scope : scopes) {
            if (scopeToResource.containsKey(scope)) {
                resourceIds.add(scopeToResource.get(scope));
            } else if (scope.contains(scopeSeparator) && !scope.endsWith(scopeSeparator) && !"uaa.none".equals(scope)) {
                String id = scope.substring(0, scope.lastIndexOf(scopeSeparator));
                resourceIds.add(id);
            }
        }
        return resourceIds.isEmpty() ? clientDetails.getResourceIds() : resourceIds;
    }

    public OAuth2Request createOAuth2Request(AuthorizationRequest request) {
        return request.createOAuth2Request();
    }

    public OAuth2Request createOAuth2Request(ClientDetails client, TokenRequest tokenRequest) {
        return tokenRequest.createOAuth2Request(client);
    }

    public TokenRequest createTokenRequest(Map<String, String> requestParameters, ClientDetails authenticatedClient) {
        ClientDetails targetClient = authenticatedClient;
        //clone so we can modify it
        requestParameters = new HashMap<>(requestParameters);
        String clientId = requestParameters.get(OAuth2Utils.CLIENT_ID);
        String grantType = requestParameters.get(GRANT_TYPE);
        if (clientId != null) {
            if (TokenConstants.GRANT_TYPE_USER_TOKEN.equals(grantType)) {
                targetClient = clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
                requestParameters.put(TokenConstants.USER_TOKEN_REQUESTING_CLIENT_ID, authenticatedClient.getClientId());
            } else if (GRANT_TYPE_TOKEN_EXCHANGE.equals(grantType)) {
                String audience = requestParameters.get("audience");
                if (hasText(audience)) {
                    try {
                        targetClient = clientDetailsService.loadClientByClientId(audience, identityZoneManager.getCurrentIdentityZoneId());
                    } catch (ClientRegistrationException r) {
                        throw new InvalidClientException("Invalid audience("+audience+") for "+ GRANT_TYPE_TOKEN_EXCHANGE+ " grant.");
                    }
                }
            } else if (!clientId.equals(authenticatedClient.getClientId())) {
                // otherwise, make sure that they match
                throw new InvalidClientException("Given client ID does not match authenticated client");
            }
        }
        Set<String> scopes = extractScopes(requestParameters, targetClient);
        Set<String> resourceIds = getResourceIds(targetClient, scopes);

        return new UaaTokenRequest(unmodifiableMap(requestParameters), authenticatedClient.getClientId(), scopes, grantType, resourceIds);
    }

    protected Set<String> extractScopes(Map<String, String> requestParameters, ClientDetails clientDetails) {
        boolean clientCredentials = GRANT_TYPE_CLIENT_CREDENTIALS.equals(requestParameters.get(GRANT_TYPE));
        Set<String> scopes = OAuth2Utils.parseParameterList(requestParameters.get(OAuth2Utils.SCOPE));
        if (scopes == null || scopes.isEmpty()) {
            // If no scopes are specified in the incoming data, use the default values registered with the client
            // (the spec allows us to choose between this option and rejecting the request completely, so we'll take the
            // least obnoxious choice as a default).
            if (clientCredentials) {
                Set<String> authorities = new HashSet<>();
                for (GrantedAuthority a : clientDetails.getAuthorities()) {
                    authorities.add(a.getAuthority());
                }
                scopes = authorities;
            } else {
                scopes = clientDetails.getScope();
            }
        }
        if (!clientCredentials) {
            Set<String> userScopes = getUserScopes();
            scopes = intersectScopes(scopes, clientDetails.getScope(), userScopes);
        }
        return scopes;
    }

    protected Set<String> getUserScopes() {
        Set<String> scopes = new HashSet<>();
        if (securityContextAccessor.isUser()) {
            String userId = securityContextAccessor.getUserId();
            Collection<? extends GrantedAuthority> authorities = uaaUserDatabase != null ?
                    uaaUserDatabase.retrieveUserById(userId).getAuthorities() :
                    securityContextAccessor.getAuthorities();
            for (GrantedAuthority a : authorities) {
                scopes.add(a.getAuthority());
            }
        }
        return scopes;
    }

    public TokenRequest createTokenRequest(AuthorizationRequest authorizationRequest, String grantType) {
        return new TokenRequest(authorizationRequest.getRequestParameters(), authorizationRequest.getClientId(),
                authorizationRequest.getScope(), grantType);
    }

    public class UaaTokenRequest extends TokenRequest {
        private Set<String> resourceIds;
        private Set<String> responseTypes;

        public UaaTokenRequest(Map<String, String> requestParameters, String clientId, Collection<String> scope, String grantType, Set<String> resourceIds) {
            super(requestParameters, clientId, scope, grantType);
            this.resourceIds = resourceIds;
            this.responseTypes = OAuth2Utils.parseParameterList(requestParameters.get(OAuth2Utils.RESPONSE_TYPE));
        }

        @Override
        public OAuth2Request createOAuth2Request(ClientDetails client) {
            OAuth2Request request = super.createOAuth2Request(client);
            String clientAuthentication = UaaSecurityContextUtils.getClientAuthenticationMethod();
            if (clientAuthentication != null) {
                request.getExtensions().put(ClaimConstants.CLIENT_AUTH_METHOD, clientAuthentication);
            }
            return new OAuth2Request(
                    request.getRequestParameters(),
                    client.getClientId(),
                    client.getAuthorities(),
                    true, request.getScope(),
                    resourceIds,
                    request.getRedirectUri(),
                    responseTypes,
                    request.getExtensions(),
                    this.getTokenActor()
            );
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = super.hashCode();
            result = prime * result + (resourceIds == null ? 0 : resourceIds.hashCode());
            result = prime * result + (responseTypes == null ? 0 : responseTypes.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            UaaTokenRequest other = (UaaTokenRequest) obj;
            if (!Objects.equals(resourceIds, other.resourceIds)) {
                return false;
            }
            return Objects.equals(responseTypes, other.responseTypes);
        }
    }
}
