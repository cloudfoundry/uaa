package org.cloudfoundry.identity.uaa.oauth.provider.error;

import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.ThrowableCauseExtractor;

import javax.servlet.ServletException;

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
  /**
   * @see org.springframework.security.web.util.ThrowableAnalyzer#initExtractorMap()
   */
  protected void initExtractorMap() {
    super.initExtractorMap();

    registerExtractor(ServletException.class, new ThrowableCauseExtractor() {
      public Throwable extractCause(Throwable throwable) {
        ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
        return ((ServletException) throwable).getRootCause();
      }
    });
  }
}
