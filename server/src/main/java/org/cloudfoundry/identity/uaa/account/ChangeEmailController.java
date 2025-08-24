package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import java.util.Map;

@Controller
public class ChangeEmailController {

    private final ChangeEmailService changeEmailService;
    private final UaaUserDatabase uaaUserDatabase;

    public ChangeEmailController(
            final ChangeEmailService changeEmailService,
            final UaaUserDatabase uaaUserDatabase) {
        this.changeEmailService = changeEmailService;
        this.uaaUserDatabase = uaaUserDatabase;
    }

    @GetMapping("/change_email")
    public String changeEmailPage(Model model, @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        model.addAttribute("email", ((UaaPrincipal) securityContext.getAuthentication().getPrincipal()).getEmail());
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        return "change_email";
    }

    @PostMapping("/change_email.do")
    public String changeEmail(Model model, @Valid @ModelAttribute ValidEmail newEmail, BindingResult result,
            @RequestParam(required = false, value = "client_id") String clientId,
            @RequestParam(required = false, value = "redirect_uri") String redirectUri,
            RedirectAttributes redirectAttributes, HttpServletResponse response) {
        SecurityContext securityContext = SecurityContextHolder.getContext();

        if (result.hasErrors()) {
            model.addAttribute("error_message_code", "invalid_email");
            model.addAttribute("email", ((UaaPrincipal) securityContext.getAuthentication().getPrincipal()).getEmail());
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return "change_email";
        }
        String origin = ((UaaPrincipal) securityContext.getAuthentication().getPrincipal()).getOrigin();
        if (!origin.equals(OriginKeys.UAA)) {
            redirectAttributes.addAttribute("error_message_code", "email_change.non-uaa-origin");
            return "redirect:profile";
        }

        String userId = ((UaaPrincipal) securityContext.getAuthentication().getPrincipal()).getId();
        String userEmail = ((UaaPrincipal) securityContext.getAuthentication().getPrincipal()).getName();

        try {
            changeEmailService.beginEmailChange(userId, userEmail, newEmail.getNewEmail(), clientId, redirectUri);
        } catch (UaaException e) {
            if (e.getHttpStatus() == 409) {
                model.addAttribute("error_message_code", "username_exists");
                model.addAttribute("email", ((UaaPrincipal) securityContext.getAuthentication().getPrincipal()).getEmail());
                response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
                return "change_email";
            }
        }

        return "redirect:email_sent?code=email_change";
    }

    @GetMapping("/verify_email")
    public String verifyEmail(Model model, @RequestParam String code, RedirectAttributes redirectAttributes,
            HttpServletResponse httpServletResponse, HttpServletRequest request) {
        Map<String, String> response;

        try {
            response = changeEmailService.completeVerification(code);
        } catch (UaaException e) {
            return handleExceptionConsideringAuthentication(model, httpServletResponse);
        }

        UaaUser user;
        try {
            user = uaaUserDatabase.retrieveUserById(response.get("userId"));
        } catch (UsernameNotFoundException e) {
            return handleExceptionConsideringAuthentication(model, httpServletResponse);
        }


        String redirectLocation = response.get("redirect_url");

        if (SecurityContextHolder.getContext().getAuthentication() instanceof UaaAuthentication) {
            UaaAuthentication oldAuthentication = (UaaAuthentication) SecurityContextHolder.getContext().getAuthentication();
            String authenticatedId = oldAuthentication.getPrincipal().getId();
            if (authenticatedId.equals(user.getId())) {
                UaaAuthenticationDetails details = new UaaAuthenticationDetails(request);
                UaaAuthentication success = new UaaAuthentication(new UaaPrincipal(user), user.getAuthorities(), details);
                success.setAuthenticationMethods(oldAuthentication.getAuthenticationMethods());
                SecurityContextHolder.getContext().setAuthentication(success);
            }
            if (redirectLocation == null) {
                redirectLocation = "profile";
                redirectAttributes.addAttribute("success_message_code", "email_change.success");
            }
            return "redirect:" + redirectLocation;
        } else {
            if (redirectLocation == null) {
                return "redirect:login?success=change_email_success";
            } else {
                return "redirect:login?success=change_email_success&form_redirect_uri=" + redirectLocation;
            }
        }
    }

    private String handleExceptionConsideringAuthentication(Model model, HttpServletResponse httpServletResponse) {
        if (SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken) {
            model.addAttribute("error_message_code", "email_change.invalid_code");
            httpServletResponse.setStatus(422);
            return "error";
        } else {
            return "redirect:profile?error_message_code=email_change.invalid_code";
        }
    }

    public static class ValidEmail {
        @Email
        String newEmail;

        public String getNewEmail() {
            return newEmail;
        }

        public void setNewEmail(String email) {
            this.newEmail = email;
        }
    }
}
