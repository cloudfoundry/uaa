package org.cloudfoundry.identity.uaa.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

public class UaaSavedRequestAwareAuthenticationSuccessHandler
    extends SavedRequestAwareAuthenticationSuccessHandler {

  public static final String SAVED_REQUEST_SESSION_ATTRIBUTE = "SPRING_SECURITY_SAVED_REQUEST";

  public static final String URI_OVERRIDE_ATTRIBUTE = "override.redirect_uri";

  public static final String FORM_REDIRECT_PARAMETER = "form_redirect_uri";

  private static Logger logger =
      LoggerFactory.getLogger(UaaSavedRequestAwareAuthenticationSuccessHandler.class);

  @Override
  public String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
    Object redirectAttribute = request.getAttribute(URI_OVERRIDE_ATTRIBUTE);
    String redirectFormParam = request.getParameter(FORM_REDIRECT_PARAMETER);
    if (redirectAttribute != null) {
      logger.debug("Returning redirectAttribute saved URI:" + redirectAttribute);
      return (String) redirectAttribute;
    } else if (UaaUrlUtils.uriHasMatchingHost(redirectFormParam, request.getServerName())) {
      return redirectFormParam;
    } else {
      return super.determineTargetUrl(request, response);
    }
  }
}
