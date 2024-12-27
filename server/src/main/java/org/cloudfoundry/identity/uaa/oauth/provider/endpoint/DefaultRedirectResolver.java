package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server token endpoint
 */
public class DefaultRedirectResolver implements RedirectResolver {

    private Collection<String> redirectGrantTypes = Arrays.asList("implicit", "authorization_code");

    private boolean matchSubdomains;

    private boolean matchPorts = true;

    /**
     * Flag to indicate that requested URIs will match if they are a subdomain of the registered value.
     * 
     * @param matchSubdomains the flag value to set (default true)
     */
    public void setMatchSubdomains(boolean matchSubdomains) {
        this.matchSubdomains = matchSubdomains;
    }

    /**
     * Flag that enables/disables port matching between the requested redirect URI and the registered redirect URI(s).
     *
     * @param matchPorts true to enable port matching, false to disable (defaults to true)
     */
    public void setMatchPorts(boolean matchPorts) {
        this.matchPorts = matchPorts;
    }

    /**
     * Grant types that are permitted to have a redirect uri.
     * 
     * @param redirectGrantTypes the redirect grant types to set
     */
    public void setRedirectGrantTypes(Collection<String> redirectGrantTypes) {
        this.redirectGrantTypes = new HashSet<>(redirectGrantTypes);
    }

    public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {

        Set<String> authorizedGrantTypes = client.getAuthorizedGrantTypes();
        if (authorizedGrantTypes.isEmpty()) {
            throw new InvalidGrantException("A client must have at least one authorized grant type.");
        }
        if (!containsRedirectGrantType(authorizedGrantTypes)) {
            throw new InvalidGrantException(
                    "A redirect_uri can only be used by implicit or authorization_code grant types.");
        }

        Set<String> registeredRedirectUris = client.getRegisteredRedirectUri();
        if (registeredRedirectUris == null || registeredRedirectUris.isEmpty()) {
            throw new InvalidRequestException("At least one redirect_uri must be registered with the client.");
        }
        return obtainMatchingRedirect(registeredRedirectUris, requestedRedirect);
    }

    /**
     * @param grantTypes some grant types
     * @return true if the supplied grant types includes one or more of the redirect types
     */
    private boolean containsRedirectGrantType(Set<String> grantTypes) {
        for (String type : grantTypes) {
            if (redirectGrantTypes.contains(type)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the requested redirect URI "matches" the specified redirect URI. For a URL, this implementation tests if
     * the user requested redirect starts with the registered redirect, so it would have the same host and root path if
     * it is an HTTP URL. The port, userinfo, query params also matched. Request redirect uri path can include
     * additional parameters which are ignored for the match
     * <p>
     * For other (non-URL) cases, such as for some implicit clients, the redirect_uri must be an exact match.
     * 
     * @param requestedRedirect The requested redirect URI.
     * @param redirectUri The registered redirect URI.
     * @return Whether the requested redirect URI "matches" the specified redirect URI.
     */
    protected boolean redirectMatches(String requestedRedirect, String redirectUri) {
        UriComponents requestedRedirectUri = UriComponentsBuilder.fromUriString(requestedRedirect).build();
        UriComponents registeredRedirectUri = UriComponentsBuilder.fromUriString(redirectUri).build();

        boolean schemeMatch = isEqual(registeredRedirectUri.getScheme(), requestedRedirectUri.getScheme());
        boolean userInfoMatch = isEqual(registeredRedirectUri.getUserInfo(), requestedRedirectUri.getUserInfo());
        boolean hostMatch = hostMatches(registeredRedirectUri.getHost(), requestedRedirectUri.getHost());
        boolean portMatch = matchPorts = registeredRedirectUri.getPort() == requestedRedirectUri.getPort();
        boolean pathMatch = isEqual(registeredRedirectUri.getPath(),
                StringUtils.cleanPath(Optional.ofNullable(requestedRedirectUri.getPath()).orElse("")));
        boolean queryParamMatch = matchQueryParams(registeredRedirectUri.getQueryParams(),
                requestedRedirectUri.getQueryParams());

        return schemeMatch && userInfoMatch && hostMatch && portMatch && pathMatch && queryParamMatch;
    }


    /**
     * Checks whether the registered redirect uri query params key and values contains match the requested set
     *
     * The requested redirect uri query params are allowed to contain additional params which will be retained
     *
     * @param registeredRedirectUriQueryParams
     * @param requestedRedirectUriQueryParams
     * @return whether the params match
     */
    private boolean matchQueryParams(MultiValueMap<String, String> registeredRedirectUriQueryParams,
            MultiValueMap<String, String> requestedRedirectUriQueryParams) {


        Iterator<String> iter = registeredRedirectUriQueryParams.keySet().iterator();
        while (iter.hasNext()) {
            String key = iter.next();
            List<String> registeredRedirectUriQueryParamsValues = registeredRedirectUriQueryParams.get(key);
            List<String> requestedRedirectUriQueryParamsValues = requestedRedirectUriQueryParams.get(key);

            if (!registeredRedirectUriQueryParamsValues.equals(requestedRedirectUriQueryParamsValues)) {
                return false;
            }
        }

        return true;
    }


    /**
     * Compares two strings but treats empty string or null equal
     *
     * @param str1
     * @param str2
     * @return true if strings are equal, false otherwise
     */
    private boolean isEqual(String str1, String str2) {
        return Objects.equals(str1, str2);
    }

    /**
     * Check if host matches the registered value.
     * 
     * @param registered the registered host. Can be null.
     * @param requested the requested host. Can be null.
     * @return true if they match
     */
    protected boolean hostMatches(String registered, String requested) {
        if (matchSubdomains) {
            return isEqual(registered, requested) || (requested != null && requested.endsWith("." + registered));
        }
        return isEqual(registered, requested);
    }

    /**
     * Attempt to match one of the registered URIs to the that of the requested one.
     * 
     * @param redirectUris the set of the registered URIs to try and find a match. This cannot be null or empty.
     * @param requestedRedirect the URI used as part of the request
     * @return redirect uri
     * @throws RedirectMismatchException if no match was found
     */
    private String obtainMatchingRedirect(Set<String> redirectUris, String requestedRedirect) {
        Assert.notEmpty(redirectUris, "Redirect URIs cannot be empty");

        if (redirectUris.size() == 1 && requestedRedirect == null) {
            return redirectUris.iterator().next();
        }

        for (String redirectUri : redirectUris) {
            if (requestedRedirect != null && redirectMatches(requestedRedirect, redirectUri)) {
                // Initialize with the registered redirect-uri
                UriComponentsBuilder redirectUriBuilder = UriComponentsBuilder.fromUriString(redirectUri);

                UriComponents requestedRedirectUri = UriComponentsBuilder.fromUriString(requestedRedirect).build();

                if (this.matchSubdomains) {
                    redirectUriBuilder.host(requestedRedirectUri.getHost());
                }
                if (!this.matchPorts) {
                    redirectUriBuilder.port(requestedRedirectUri.getPort());
                }
                redirectUriBuilder.replaceQuery(requestedRedirectUri.getQuery());		// retain additional params (if any)
                redirectUriBuilder.fragment(null);
                return redirectUriBuilder.build().toUriString();
            }
        }

        throw new RedirectMismatchException("Invalid redirect uri does not match one of the registered values.");
    }
}
