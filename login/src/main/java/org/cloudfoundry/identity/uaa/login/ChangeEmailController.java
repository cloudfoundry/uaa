package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.hibernate.validator.constraints.Email;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.Map;


@Controller
public class ChangeEmailController {

    private final ChangeEmailService changeEmailService;

    public ChangeEmailController(ChangeEmailService changeEmailService) {
        this.changeEmailService = changeEmailService;
    }

    @RequestMapping(value = "/change_email", method = RequestMethod.GET)
    public String changeEmailPage(Model model, @RequestParam(value = "client_id", required = false) String clientId) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        model.addAttribute("email", ((UaaPrincipal)securityContext.getAuthentication().getPrincipal()).getEmail());
        model.addAttribute("client_id", clientId);
        return "change_email";
    }

    @RequestMapping(value = "/change_email.do", method = RequestMethod.POST)
    public String changeEmail(Model model, @Valid @ModelAttribute("newEmail") ValidEmail newEmail, BindingResult result, @RequestParam("client_id") String clientId, RedirectAttributes redirectAttributes, HttpServletResponse response) {
        SecurityContext securityContext = SecurityContextHolder.getContext();

        if(result.hasErrors()) {
            model.addAttribute("error_message_code", "invalid_email");
            model.addAttribute("email", ((UaaPrincipal)securityContext.getAuthentication().getPrincipal()).getEmail());
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return "change_email";
        }
        String origin = ((UaaPrincipal)securityContext.getAuthentication().getPrincipal()).getOrigin();
        if (!origin.equals(Origin.UAA)) {
            redirectAttributes.addAttribute("error_message_code", "email_change.non-uaa-origin");
            return "redirect:profile";
        }

        String userId = ((UaaPrincipal)securityContext.getAuthentication().getPrincipal()).getId();
        String userEmail = ((UaaPrincipal)securityContext.getAuthentication().getPrincipal()).getName();

        try {
            changeEmailService.beginEmailChange(userId, userEmail, newEmail.getNewEmail(), clientId);
        } catch (UaaException e) {
            if (e.getHttpStatus() == 409) {
                model.addAttribute("error_message_code", "username_exists");
                model.addAttribute("email", ((UaaPrincipal)securityContext.getAuthentication().getPrincipal()).getEmail());
                response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
                return "change_email";
            }
        }

        return "redirect:email_sent?code=email_change";
    }

    @RequestMapping(value = "/verify_email", method = RequestMethod.GET)
    public String verifyEmail(Model model, @RequestParam("code") String code, RedirectAttributes redirectAttributes, HttpServletResponse httpServletResponse) {
        Map<String,String> response;

        try {
            response = changeEmailService.completeVerification(code);
        } catch (UaaException e) {
            if (SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken) {
                model.addAttribute("error_message_code", "email_change.invalid_code");
                httpServletResponse.setStatus(422);
                return "error";
            }
            else {
                return "redirect:profile?error_message_code=email_change.invalid_code";
            }
        }

        UaaPrincipal uaaPrincipal = new UaaPrincipal(response.get("userId"), response.get("username"), response.get("email"), Origin.UAA, null);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        String redirectLocation = response.get("redirect_url");
        if (redirectLocation == null) {
            redirectLocation = "profile";
            redirectAttributes.addAttribute("success_message_code", "email_change.success");
        }
        return "redirect:" + redirectLocation;
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
