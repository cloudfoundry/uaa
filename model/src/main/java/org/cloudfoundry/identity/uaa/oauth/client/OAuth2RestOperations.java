package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.springframework.web.client.RestOperations;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public interface OAuth2RestOperations extends RestOperations {

    OAuth2AccessToken getAccessToken() throws UserRedirectRequiredException;

    OAuth2ClientContext getOAuth2ClientContext();

    OAuth2ProtectedResourceDetails getResource();

}
