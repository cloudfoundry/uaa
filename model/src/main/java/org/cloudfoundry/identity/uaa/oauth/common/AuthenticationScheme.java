package org.cloudfoundry.identity.uaa.oauth.common;

/**
 * Moved class AuthenticationScheme implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 */
public enum AuthenticationScheme {

    /**
     * Send an Authorization header.
     */
    header,

    /**
     * Send a query parameter in the URI.
     */
    query,

    /**
     * Send in the form body.
     */
    form,

    /**
     * Do not send at all.
     */
    none
}