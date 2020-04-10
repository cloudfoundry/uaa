package org.cloudfoundry.identity.uaa.account;

import java.io.IOException;
import java.sql.Timestamp;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation.PasswordConfirmationException;
import org.cloudfoundry.identity.uaa.authentication.InvalidCodeException;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

public class ResetPasswordAuthenticationFilter extends OncePerRequestFilter {

  private final ResetPasswordService service;
  private final AuthenticationSuccessHandler handler;
  private final AuthenticationEntryPoint entryPoint;
  private final ExpiringCodeStore expiringCodeStore;

  public ResetPasswordAuthenticationFilter(
      ResetPasswordService service,
      AuthenticationSuccessHandler handler,
      AuthenticationEntryPoint entryPoint,
      ExpiringCodeStore expiringCodeStore) {
    this.service = service;
    this.handler = handler;
    this.entryPoint = entryPoint;
    this.expiringCodeStore = expiringCodeStore;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String email = request.getParameter("email");
    String code = request.getParameter("code");
    String password = request.getParameter("password");
    String passwordConfirmation = request.getParameter("password_confirmation");

    PasswordConfirmationValidation validation =
        new PasswordConfirmationValidation(email, password, passwordConfirmation);
    ExpiringCode expiringCode = null;
    try {
      expiringCode = expiringCodeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
      validation.throwIfNotValid();
      if (expiringCode == null) {
        throw new InvalidCodeException(
            "invalid_code",
            "Sorry, your reset password link is no longer valid. Please request a new one",
            422);
      }
      ResetPasswordService.ResetPasswordResponse resetPasswordResponse =
          service.resetPassword(expiringCode, password);
      String redirectUri = resetPasswordResponse.getRedirectUri();
      if (!StringUtils.hasText(redirectUri) || redirectUri.equals("home")) {
        response.sendRedirect(request.getContextPath() + "/login?success=password_reset");
      } else {
        response.sendRedirect(
            request.getContextPath()
                + "/login?success=password_reset&form_redirect_uri="
                + redirectUri);
      }
    } catch (InvalidPasswordException e) {
      refreshCode(request, expiringCode);
      entryPoint.commence(
          request, response, new BadCredentialsException(e.getMessagesAsOneString(), e));
    } catch (UaaException e) {
      entryPoint.commence(
          request, response, new InternalAuthenticationServiceException(e.getMessage(), e));
    } catch (PasswordConfirmationException pe) {
      refreshCode(request, expiringCode);
      entryPoint.commence(
          request, response, new BadCredentialsException("Password did not pass validation.", pe));
    }
    return;
  }

  private void refreshCode(HttpServletRequest request, ExpiringCode expiringCode) {
    ExpiringCode newCode =
        expiringCodeStore.generateCode(
            expiringCode.getData(),
            new Timestamp(System.currentTimeMillis() + 1000 * 60 * 10),
            expiringCode.getIntent(),
            IdentityZoneHolder.get().getId());
    request.setAttribute("code", newCode.getCode());
  }
}
