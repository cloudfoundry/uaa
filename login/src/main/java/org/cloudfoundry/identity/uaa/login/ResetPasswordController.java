/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.Map;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletResponse;

@Controller
public class ResetPasswordController {
    protected final Log logger = LogFactory.getLog(getClass());

    private final ResetPasswordService resetPasswordService;
    private final MessageService messageService;
    private final TemplateEngine templateEngine;
    private final UaaUrlUtils uaaUrlUtils;
    private final String brand;
    private final Pattern emailPattern;

    public ResetPasswordController(ResetPasswordService resetPasswordService, MessageService messageService, TemplateEngine templateEngine, UaaUrlUtils uaaUrlUtils, String brand) {
        this.resetPasswordService = resetPasswordService;
        this.messageService = messageService;
        this.templateEngine = templateEngine;
        this.uaaUrlUtils = uaaUrlUtils;
        this.brand = brand;
        emailPattern = Pattern.compile("^\\S+@\\S+\\.\\S+$");
    }

    @RequestMapping(value = "/forgot_password", method = RequestMethod.GET)
    public String forgotPasswordPage() {
        return "forgot_password";
    }

    @RequestMapping(value = "/forgot_password.do", method = RequestMethod.POST)
    public String forgotPassword(Model model, @RequestParam("email") String email, HttpServletResponse response) {
        if (emailPattern.matcher(email).matches()) {
            forgotPassword(email);
            return "redirect:email_sent?code=reset_password";
        } else {
            return handleUnprocessableEntity(model, response, "message_code", "form_error");
        }
    }

    private void forgotPassword(String email) {
        String subject = getSubjectText();
        String htmlContent = null;
        String userId = null;

        try {
            ForgotPasswordInfo forgotPasswordInfo = resetPasswordService.forgotPassword(email);
            userId = forgotPasswordInfo.getUserId();
            htmlContent = getCodeSentEmailHtml(forgotPasswordInfo.getResetPasswordCode().getCode(), email);
        } catch (ConflictException e) {
            htmlContent = getResetUnavailableEmailHtml(email);
            userId = e.getUserId();
        } catch (NotFoundException e) {
            logger.error("User with email address " + email + " not found.");
        }

        if (htmlContent != null && userId != null) {
            messageService.sendMessage(email, MessageType.PASSWORD_RESET, subject, htmlContent);
        }
    }

    private String getSubjectText() {
        String serviceName = getServiceName();
        if (StringUtils.isEmpty(serviceName)) {
            return "Account password reset request";
        }
        return serviceName + " account password reset request";
    }

    private String getCodeSentEmailHtml(String code, String email) {
        String resetUrl = uaaUrlUtils.getUaaUrl("/reset_password");

        final Context ctx = new Context();
        ctx.setVariable("serviceName", getServiceName());
        ctx.setVariable("code", code);
        ctx.setVariable("email", email);
        ctx.setVariable("resetUrl", resetUrl);
        return templateEngine.process("reset_password", ctx);
    }

    private String getResetUnavailableEmailHtml(String email) {
        String hostname = uaaUrlUtils.getUaaHost();

        final Context ctx = new Context();
        ctx.setVariable("serviceName", getServiceName());
        ctx.setVariable("email", email);
        ctx.setVariable("hostname", hostname);
        return templateEngine.process("reset_password_unavailable", ctx);
    }

    private String getServiceName() {
        if (IdentityZoneHolder.get().equals(IdentityZone.getUaa())) {
            return brand.equals("pivotal") ? "Pivotal" : "";
        } else {
            return IdentityZoneHolder.get().getName();
        }
    }

    @RequestMapping(value = "/email_sent", method = RequestMethod.GET)
    public String emailSentPage(@ModelAttribute("code") String code) {
        return "email_sent";
    }

    @RequestMapping(value = "/reset_password", method = RequestMethod.GET, params = { "email", "code" })
    public String resetPasswordPage() {
        return "reset_password";
    }

    @RequestMapping(value = "/reset_password.do", method = RequestMethod.POST)
    public String resetPassword(Model model,
                                @RequestParam("code") String code,
                                @RequestParam("email") String email,
                                @RequestParam("password") String password,
                                @RequestParam("password_confirmation") String passwordConfirmation,
                                HttpServletResponse response) {

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(password, passwordConfirmation);
        if (!validation.valid()) {
            model.addAttribute("message_code", validation.getMessageCode());
            model.addAttribute("email", email);
            model.addAttribute("code", code);
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return "reset_password";
        }

        try {
            ScimUser user = resetPasswordService.resetPassword(code, password);

            UaaPrincipal uaaPrincipal = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), Origin.UAA, null, IdentityZoneHolder.get().getId());
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
            SecurityContextHolder.getContext().setAuthentication(token);

            return "redirect:home";
        } catch (UaaException e) {
            return handleUnprocessableEntity(model, response, "message_code", "bad_code");
        } catch (InvalidPasswordException e) {
            return handleUnprocessableEntity(model, response, "message", e.getMessagesAsOneString());
        }
    }

    private String handleUnprocessableEntity(Model model, HttpServletResponse response, String attributeKey, String attributeValue) {
        model.addAttribute(attributeKey, attributeValue);
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return "forgot_password";
    }
}
