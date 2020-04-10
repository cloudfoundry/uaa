package org.cloudfoundry.identity.uaa.authentication;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.security.core.GrantedAuthority;

public interface UaaAuthenticationJsonBase {

  String DETAILS = "details";
  String PRINCIPAL = "principal";
  String AUTHORITIES = "authorities";
  String EXTERNAL_GROUPS = "externalGroups";
  String EXPIRES_AT = "expiresAt";
  String AUTH_TIME = "authenticatedTime";
  String AUTHENTICATED = "authenticated";
  String USER_ATTRIBUTES = "userAttributes";
  String AUTHENTICATION_METHODS = "authenticationMethods";
  String AUTHN_CONTEXT_CLASS_REF = "authContextClassRef";
  String PREVIOIUS_LOGIN_SUCCESS_TIME = "previousLoginSuccessTime";
  String NULL_STRING = "null";

  default Set<String> serializeAuthorites(Collection<? extends GrantedAuthority> authorities) {
    return UaaStringUtils.getStringsFromAuthorities(authorities);
  }

  default List<? extends GrantedAuthority> deserializeAuthorites(Collection<String> authorities) {
    return UaaStringUtils.getAuthoritiesFromStrings(authorities);
  }
}
