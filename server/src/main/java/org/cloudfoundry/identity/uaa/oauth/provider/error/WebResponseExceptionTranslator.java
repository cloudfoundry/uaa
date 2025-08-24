package org.cloudfoundry.identity.uaa.oauth.provider.error;

import org.springframework.http.ResponseEntity;

/**
 * Base exception for OAuth 2 exceptions.
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server exceptions
 */
public interface WebResponseExceptionTranslator<T> {

    ResponseEntity<T> translate(Exception e) throws Exception;

}
