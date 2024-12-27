package org.cloudfoundry.identity.uaa.oauth.client.test;

import org.springframework.web.client.RestOperations;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: Test
 */
public interface RestTemplateHolder {

    void setRestTemplate(RestOperations restTemplate);

    RestOperations getRestTemplate();

}
