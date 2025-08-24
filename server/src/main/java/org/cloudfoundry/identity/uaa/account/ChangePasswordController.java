package org.cloudfoundry.identity.uaa.account;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ChangePasswordController {

    private final ChangePasswordService changePasswordService;

    public ChangePasswordController(final ChangePasswordService changePasswordService) {
        this.changePasswordService = changePasswordService;
    }

    @GetMapping("/change_password")
    public String changePasswordPage() {
        return "change_password";
    }

    @PostMapping("/change_password.do")
    public String changePassword(
            Model model,
            @RequestParam("current_password") String currentPassword,
            @RequestParam("new_password") String newPassword,
            @RequestParam("confirm_password") String confirmPassword,
            HttpServletResponse response,
            HttpServletRequest request) {

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(newPassword, confirmPassword);
        if (!validation.valid()) {
            model.addAttribute("message_code", validation.getMessageCode());
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return "change_password";
        }

        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();
        String username = authentication.getName();

        try {
            changePasswordService.changePassword(username, currentPassword, newPassword);
            request.getSession().invalidate();
            //request.logout();
            request.getSession(true);
            if (authentication instanceof UaaAuthentication uaaAuthentication) {
                uaaAuthentication.setAuthenticatedTime(System.currentTimeMillis());
                uaaAuthentication.setAuthenticationDetails(new UaaAuthenticationDetails(request));
            }
            securityContext.setAuthentication(authentication);
            return "redirect:profile";
        } catch (BadCredentialsException e) {
            model.addAttribute("message_code", "unauthorized");
        } catch (InvalidPasswordException e) {
            model.addAttribute("message", e.getMessagesAsOneString());
        }
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return "change_password";
    }
}
