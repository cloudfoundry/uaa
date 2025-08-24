package org.cloudfoundry.identity.uaa.oauth.provider.authentication;


import org.springframework.security.authentication.AuthenticationDetailsSource;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class OAuth2AuthenticationDetailsSource implements
        AuthenticationDetailsSource<HttpServletRequest, OAuth2AuthenticationDetails> {

    public OAuth2AuthenticationDetails buildDetails(HttpServletRequest context) {
        return new OAuth2AuthenticationDetails(context);
    }

}
