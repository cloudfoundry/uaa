package org.cloudfoundry.identity.uaa.account;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation.PasswordConfirmationException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

public class ResetPasswordAuthenticationEntryPoint implements AuthenticationEntryPoint {

  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException)
      throws IOException, ServletException {
    Throwable cause = authException.getCause();
    response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());

    HttpServletRequestWrapper wrapper =
        new HttpServletRequestWrapper(request) {
          @Override
          public String getMethod() {
            return "GET";
          }

          @Override
          public String getParameter(String name) {
            if (name.equals("code")) {
              return (String) getAttribute(name);
            }
            return super.getParameter(name);
          }

          @Override
          public Map<String, String[]> getParameterMap() {
            Map<String, String[]> map = super.getParameterMap();
            if (map.containsKey("code")) {
              Map<String, String[]> newMap = new HashMap<>(map);
              newMap.put("code", new String[] {(String) getAttribute("code")});
              map = newMap;
            }
            return map;
          }

          @Override
          public String[] getParameterValues(String name) {
            return getParameterMap().get(name);
          }
        };

    if (cause instanceof PasswordConfirmationException) {
      PasswordConfirmationException passwordConfirmationException =
          (PasswordConfirmationException) cause;
      request.setAttribute("message_code", passwordConfirmationException.getMessageCode());

      request.getRequestDispatcher("/reset_password").forward(wrapper, response);
      return;
    } else {
      if (cause instanceof InvalidPasswordException) {
        InvalidPasswordException exception = (InvalidPasswordException) cause;
        request.setAttribute("message", exception.getMessagesAsOneString());
        request.getRequestDispatcher("/reset_password").forward(wrapper, response);
      } else {
        request.setAttribute("message_code", "bad_code");
        request.getRequestDispatcher("/forgot_password").forward(wrapper, response);
      }
    }
  }
}
