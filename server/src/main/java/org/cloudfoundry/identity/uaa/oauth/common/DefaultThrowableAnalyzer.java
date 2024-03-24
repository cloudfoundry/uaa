package org.cloudfoundry.identity.uaa.oauth.common;

import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.ThrowableCauseExtractor;

import javax.servlet.ServletException;

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