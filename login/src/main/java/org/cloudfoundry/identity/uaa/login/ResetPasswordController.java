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

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletResponse;

@Controller
public class ResetPasswordController {

    private final ResetPasswordService resetPasswordService;
    private final Pattern emailPattern;

    public ResetPasswordController(ResetPasswordService resetPasswordService) {
        this.resetPasswordService = resetPasswordService;
        emailPattern = Pattern.compile("^\\S+@\\S+\\.\\S+$");
    }

    @RequestMapping(value = "/forgot_password", method = RequestMethod.GET)
    public String forgotPasswordPage() {
        return "forgot_password";
    }

    @RequestMapping(value = "/forgot_password.do", method = RequestMethod.POST)
    public String forgotPassword(Model model, @RequestParam("email") String email, HttpServletResponse response) {
        if (emailPattern.matcher(email).matches()) {
            resetPasswordService.forgotPassword(email);
            return "redirect:email_sent?code=reset_password";
        } else {
            model.addAttribute("message_code", "form_error");
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return "forgot_password";
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

        ChangePasswordValidation validation = new ChangePasswordValidation(password, passwordConfirmation);
        if (!validation.valid()) {
            model.addAttribute("message_code", validation.getMessageCode());
            model.addAttribute("email", email);
            model.addAttribute("code", code);
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return "reset_password";
        }

        try {
            Map<String,String> resetResponse = resetPasswordService.resetPassword(code, password);

            UaaPrincipal uaaPrincipal = new UaaPrincipal(resetResponse.get("user_id"), resetResponse.get("username"), resetResponse.get("username"), Origin.UAA, null);
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
            SecurityContextHolder.getContext().setAuthentication(token);

            return "redirect:home";
        } catch (UaaException e) {
            model.addAttribute("message_code", "bad_code");
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return "forgot_password";
        }
    }
}
