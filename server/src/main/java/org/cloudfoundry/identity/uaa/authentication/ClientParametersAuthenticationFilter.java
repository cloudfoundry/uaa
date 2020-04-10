package org.cloudfoundry.identity.uaa.authentication;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.flywaydb.core.internal.util.StringUtils;
import org.springframework.http.MediaType;

/**
 * Filter which processes and authenticates a client based on parameters client_id and client_secret
 * It sets the authentication to a client only Oauth2Authentication object as that is expected by
 * the LoginAuthenticationManager.
 */
public class ClientParametersAuthenticationFilter
    extends AbstractClientParametersAuthenticationFilter {

  @Override
  public void wrapClientCredentialLogin(
      HttpServletRequest req,
      HttpServletResponse res,
      Map<String, String> loginInfo,
      String clientId) {
    if (!StringUtils.hasText(req.getHeader("Authorization")) && isUrlEncodedForm(req)) {
      doClientCredentialLogin(req, loginInfo, clientId);
    }
  }

  private boolean isUrlEncodedForm(HttpServletRequest req) {
    boolean isUrlEncodedForm = false;
    if (req.getHeader("Content-Type") != null) {
      isUrlEncodedForm =
          req.getHeader("Content-Type").startsWith(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
    }
    return isUrlEncodedForm;
  }
}
