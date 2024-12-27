package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public interface OAuth2RefreshToken {

    /**
     * The value of the token.
     * 
     * @return The value of the token.
     */
    @JsonValue
    String getValue();

}