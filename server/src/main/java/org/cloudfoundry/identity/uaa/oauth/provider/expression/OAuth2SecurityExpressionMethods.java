package org.cloudfoundry.identity.uaa.oauth.provider.expression;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InsufficientScopeException;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class OAuth2SecurityExpressionMethods {

    private final Authentication authentication;

    private final Set<String> missingScopes = new LinkedHashSet<>();

    public OAuth2SecurityExpressionMethods(Authentication authentication) {
        this.authentication = authentication;
    }

    /**
     * Check if any scope decisions have been denied in the current context and throw an exception if so. This method
     * automatically wraps any expressions when using {@link OAuth2MethodSecurityExpressionHandler} or
     * {@link OAuth2WebSecurityExpressionHandler}.
     * 
     * OAuth2Example usage:
     * 
     * <pre>
     * access = &quot;#oauth2.hasScope('read') or (#oauth2.hasScope('other') and hasRole('ROLE_USER'))&quot;
     * </pre>
     * 
     * Will automatically be wrapped to ensure that explicit errors are propagated rather than a generic error when
     * returning false:
     * 
     * <pre>
     * access = &quot;#oauth2.throwOnError(#oauth2.hasScope('read') or (#oauth2.hasScope('other') and hasRole('ROLE_USER'))&quot;
     * </pre>
     * 
     * N.B. normally this method will be automatically wrapped around all your access expressions. You could use it
     * explicitly to get more control, or if you have registered your own <code>ExpressionParser</code> you might need
     * it.
     * 
     * @param decision the existing access decision
     * @return true if the OAuth2 token has one of these scopes
     * @throws InsufficientScopeException if the scope is invalid and we the flag is set to throw the exception
     */
    public boolean throwOnError(boolean decision) {
        if (!decision && !missingScopes.isEmpty()) {
            Throwable failure = new InsufficientScopeException("Insufficient scope for this resource", missingScopes);
            throw new AccessDeniedException(failure.getMessage(), failure);
        }
        return decision;
    }

    /**
     * Check if the OAuth2 client (not the user) has the role specified. To check the user's roles see
     * {@link #clientHasAnyRole(String...)}.
     * 
     * @param role the role to check
     * @return true if the OAuth2 client has this role
     */
    public boolean clientHasRole(String role) {
        return clientHasAnyRole(role);
    }

    /**
     * Check if the OAuth2 client (not the user) has one of the roles specified. To check the user's roles see
     * {@link OAuth2ExpressionUtils#clientHasAnyRole(Authentication, String...)}.
     * 
     * @param roles the roles to check
     * @return true if the OAuth2 client has one of these roles
     */
    public boolean clientHasAnyRole(String... roles) {
        return OAuth2ExpressionUtils.clientHasAnyRole(authentication, roles);
    }

    /**
     * Check if the current OAuth2 authentication has the scope specified.
     * 
     * @param scope the scope to check
     * @return true if the OAuth2 authentication has the required scope
     */
    public boolean hasScope(String scope) {
        return hasAnyScope(scope);
    }

    /**
     * Check if the current OAuth2 authentication has one of the scopes specified.
     * 
     * @param scopes the scopes to check
     * @return true if the OAuth2 token has one of these scopes
     * @throws AccessDeniedException if the scope is invalid and we the flag is set to throw the exception
     */
    public boolean hasAnyScope(String... scopes) {
        boolean result = OAuth2ExpressionUtils.hasAnyScope(authentication, scopes);
        if (!result) {
            missingScopes.addAll(Arrays.asList(scopes));
        }
        return result;
    }

    /**
     * Check if the current OAuth2 authentication has one of the scopes matching a specified regex expression.
     * 
     * <pre>
     * access = &quot;#oauth2.hasScopeMatching('.*_admin:manage_scopes')))&quot;
     * </pre>
     * 
     * @param scopeRegex the scope regex to match
     * @return true if the OAuth2 authentication has the required scope
     */
    public boolean hasScopeMatching(String scopeRegex) {
        return hasAnyScopeMatching(scopeRegex);
    }

    /**
     * Check if the current OAuth2 authentication has one of the scopes matching a specified regex expression.
     * 
     * <pre>
     * access = &quot;#oauth2.hasAnyScopeMatching('admin:manage_scopes','.*_admin:manage_scopes','.*_admin:read_scopes')))&quot;
     * </pre>
     * 
     * @param scopesRegex the scopes regex to match
     * @return true if the OAuth2 token has one of these scopes
     * @throws AccessDeniedException if the scope is invalid and we the flag is set to throw the exception
     */
    public boolean hasAnyScopeMatching(String... scopesRegex) {

        boolean result = OAuth2ExpressionUtils.hasAnyScopeMatching(authentication, scopesRegex);
        if (!result) {
            missingScopes.addAll(Arrays.asList(scopesRegex));
        }
        return result;
    }

    /**
     * Deny access to oauth requests, so used for example to only allow web UI users to access a resource.
     * 
     * @return true if the current authentication is not an OAuth2 type
     */
    public boolean denyOAuthClient() {
        return !OAuth2ExpressionUtils.isOAuth(authentication);
    }

    /**
     * Permit access to oauth requests, so used for example to only allow machine clients to access a resource.
     * 
     * @return true if the current authentication is not an OAuth2 type
     */
    public boolean isOAuth() {
        return OAuth2ExpressionUtils.isOAuth(authentication);
    }

    /**
     * Check if the current authentication is acting on behalf of an authenticated user.
     * 
     * @return true if the current authentication represents a user
     */
    public boolean isUser() {
        return OAuth2ExpressionUtils.isOAuthUserAuth(authentication);
    }

    /**
     * Check if the current authentication is acting as an authenticated client application not on behalf of a user.
     * 
     * @return true if the current authentication represents a client application
     */
    public boolean isClient() {
        return OAuth2ExpressionUtils.isOAuthClientAuth(authentication);
    }
}
