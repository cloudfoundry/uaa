package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.springframework.stereotype.Component;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
@Component
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface FrameworkEndpoint {

}
