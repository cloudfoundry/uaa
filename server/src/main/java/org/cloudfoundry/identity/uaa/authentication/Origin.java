package org.cloudfoundry.identity.uaa.authentication;

import java.lang.reflect.Method;
import org.cloudfoundry.identity.uaa.oauth.RemoteUserAuthentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.ReflectionUtils;

public class Origin {

  public static String getUserId(Authentication authentication) {
    String id;
    if (authentication.getPrincipal() instanceof UaaPrincipal) {
      return ((UaaPrincipal) authentication.getPrincipal()).getId();
    } else if (authentication instanceof RemoteUserAuthentication) {
      RemoteUserAuthentication remoteUserAuthentication = (RemoteUserAuthentication) authentication;
      return remoteUserAuthentication.getId();
    } else if (authentication instanceof UaaAuthentication) {
      UaaAuthentication uaaAuthentication = (UaaAuthentication) authentication;
      return uaaAuthentication.getPrincipal().getId();
    } else if (authentication instanceof UsernamePasswordAuthenticationToken) {
      UsernamePasswordAuthenticationToken auth =
          (UsernamePasswordAuthenticationToken) authentication;
      if (auth.getPrincipal() instanceof UaaPrincipal) {
        return ((UaaPrincipal) auth.getPrincipal()).getId();
      }
    } else if ((id = getUserIdThroughReflection(authentication, "getId")) != null) {
      return id;
    }
    throw new IllegalArgumentException(
        "Can not handle authentication["
            + authentication
            + "] of class:"
            + authentication.getClass());
  }

  public static String getUserIdThroughReflection(
      Authentication authentication, String methodName) {
    try {
      Method m = ReflectionUtils.findMethod(authentication.getClass(), methodName);
      if (m == null) {
        return null;
      }
      Object id = ReflectionUtils.invokeMethod(m, authentication);
      if (id != null) {
        return id.toString();
      }
    } catch (Exception ignored) {
    }
    return null;
  }
}
