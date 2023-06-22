package org.cloudfoundry.identity.uaa.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.io.Serializable;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_AUTHENTICATION;

public final class UaaSecurityContextUtils {

  private UaaSecurityContextUtils() {}

  public static String getClientAuthenticationMethod() {
    Authentication a = SecurityContextHolder.getContext().getAuthentication();
    if (!(a instanceof OAuth2Authentication)) {
      return null;
    }
    OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) a;

    Map<String, Serializable> extensions = oAuth2Authentication.getOAuth2Request().getExtensions();
    if (extensions.isEmpty()) {
      return null;
    }

    return (String) extensions.get(CLIENT_AUTHENTICATION);
  }

}
