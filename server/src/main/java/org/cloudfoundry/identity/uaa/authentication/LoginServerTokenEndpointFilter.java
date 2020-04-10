package org.cloudfoundry.identity.uaa.authentication;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpointAuthenticationFilter;
import org.springframework.util.StringUtils;

public class LoginServerTokenEndpointFilter extends TokenEndpointAuthenticationFilter {

  private List<String> parameterNames = Collections.emptyList();

  /** @param authenticationManager an AuthenticationManager for the incoming request */
  public LoginServerTokenEndpointFilter(
      AuthenticationManager authenticationManager,
      OAuth2RequestFactory oAuth2RequestFactory,
      List<String> addNewUserParameters) {
    super(authenticationManager, oAuth2RequestFactory);
    this.parameterNames = addNewUserParameters;
  }

  @Override
  protected void onSuccessfulAuthentication(
      HttpServletRequest request, HttpServletResponse response, Authentication authResult)
      throws IOException {
    super.onSuccessfulAuthentication(request, response, authResult);
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof OAuth2Authentication) {
      ((OAuth2Authentication) auth).setAuthenticated(true);
    }
  }

  @Override
  protected Authentication extractCredentials(HttpServletRequest request) {
    String grantType = request.getParameter("grant_type");
    if (grantType != null && grantType.equals(GRANT_TYPE_PASSWORD)) {
      Map<String, String> loginInfo = new HashMap<>();
      for (String p : parameterNames) {
        String value = request.getParameter(p);
        if (StringUtils.hasText(value)) {
          loginInfo.put(p, value);
        }
      }
      return new AuthzAuthenticationRequest(loginInfo, new UaaAuthenticationDetails(request));
    }
    return null;
  }
}
