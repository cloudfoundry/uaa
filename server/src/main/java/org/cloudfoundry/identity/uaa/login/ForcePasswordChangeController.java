package org.cloudfoundry.identity.uaa.login;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Controller
@RequiredArgsConstructor
@Slf4j
public class ForcePasswordChangeController {

    private final ResourcePropertySource resourcePropertySource;
    private final ResetPasswordService resetPasswordService;
    private final IdentityZoneManager identityZoneManager;

    @GetMapping("/force_password_change")
    public String forcePasswordChangePage(Model model) {
        String email = ((UaaAuthentication) SecurityContextHolder.getContext().getAuthentication()).getPrincipal().getEmail();
        model.addAttribute("email", email);
        return "force_password_change";
    }

    @PostMapping("/force_password_change")
    public String handleForcePasswordChange(Model model,
            @RequestParam String password,
            @RequestParam("password_confirmation") String passwordConfirmation,
            HttpServletRequest request,
            HttpServletResponse response, HttpSession httpSession) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        UaaAuthentication authentication = (UaaAuthentication) securityContext.getAuthentication();
        UaaPrincipal principal = authentication.getPrincipal();
        String email = principal.getEmail();

        PasswordConfirmationValidation validation =
                new PasswordConfirmationValidation(email, password, passwordConfirmation);
        if (!validation.valid()) {
            return handleUnprocessableEntity(model, response, email, resourcePropertySource.getProperty("force_password_change.form_error").toString());
        }
        log.debug("Processing handleForcePasswordChange for user: {}", email);
        try {
            resetPasswordService.resetUserPassword(principal.getId(), password);
        } catch (InvalidPasswordException exception) {
            return handleUnprocessableEntity(model, response, email, exception.getMessagesAsOneString());
        }
        log.debug("Successful password change for username:{} in zone:{}", principal.getName(), identityZoneManager.getCurrentIdentityZone());
        SessionUtils.setPasswordChangeRequired(httpSession, false);
        authentication.setAuthenticatedTime(System.currentTimeMillis());
        SessionUtils.setSecurityContext(request.getSession(), SecurityContextHolder.getContext());
        return "redirect:/force_password_change_completed";
    }

    private String handleUnprocessableEntity(Model model, HttpServletResponse response, String email, String message) {
        model.addAttribute("message", message);
        model.addAttribute("email", email);
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return "force_password_change";
    }

}
