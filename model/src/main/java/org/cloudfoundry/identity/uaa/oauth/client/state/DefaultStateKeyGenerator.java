package org.cloudfoundry.identity.uaa.oauth.client.state;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class DefaultStateKeyGenerator implements StateKeyGenerator {

    private final RandomValueStringGenerator generator = new RandomValueStringGenerator();

    public String generateKey(OAuth2ProtectedResourceDetails resource) {
        return generator.generate();
    }

}
