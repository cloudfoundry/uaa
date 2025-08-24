package org.cloudfoundry.identity.uaa.oauth.provider.error;

import org.springframework.security.web.util.ThrowableAnalyzer;
import jakarta.servlet.ServletException;

/**
 * Base exception for OAuth 2 exceptions.
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server exceptions
 */
public final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {

    @Override
    protected void initExtractorMap() {
        super.initExtractorMap();

        registerExtractor(ServletException.class, throwable -> {
            verifyThrowableHierarchy(throwable, ServletException.class);
            return ((ServletException) throwable).getRootCause();
        });
    }
}
