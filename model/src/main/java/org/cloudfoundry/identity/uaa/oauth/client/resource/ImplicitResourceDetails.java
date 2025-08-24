package org.cloudfoundry.identity.uaa.oauth.client.resource;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class ImplicitResourceDetails extends AbstractRedirectResourceDetails {

    public ImplicitResourceDetails() {
        setGrantType("implicit");
    }

}
