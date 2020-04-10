package org.cloudfoundry.identity.uaa.client;

import static org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes.UAA_SCOPES;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class UaaScopes {

  private Set<Pattern> regExPatterns = UaaStringUtils.constructWildcards(new HashSet<>(UAA_SCOPES));

  public List<String> getUaaScopes() {
    return UAA_SCOPES;
  }

  public List<GrantedAuthority> getUaaAuthorities() {
    List<GrantedAuthority> result = new LinkedList<>();
    for (String s : getUaaScopes()) {
      result.add(new SimpleGrantedAuthority(s));
    }
    return result;
  }

  public boolean isWildcardScope(String scope) {
    return UaaStringUtils.containsWildcard(scope);
  }

  public boolean isWildcardScope(GrantedAuthority authority) {
    return isWildcardScope(authority.getAuthority());
  }

  public boolean isUaaScope(String scope) {
    return UaaStringUtils.matches(regExPatterns, scope);
  }

  public boolean isUaaScope(GrantedAuthority authority) {
    return isUaaScope(authority.getAuthority());
  }
}
