package org.cloudfoundry.identity.uaa.oauth.common.exceptions;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 exceptions
 */
@SuppressWarnings("serial")
public class UnsupportedGrantTypeException extends OAuth2Exception {

  public UnsupportedGrantTypeException(String msg, Throwable t) {
    super(msg, t);
  }

  public UnsupportedGrantTypeException(String msg) {
    super(msg);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "unsupported_grant_type";
  }
}