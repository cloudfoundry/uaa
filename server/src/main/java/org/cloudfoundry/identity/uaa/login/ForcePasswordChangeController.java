/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;

@Controller
public class ForcePasswordChangeController {

    public static final String FORCE_PASSWORD_EXPIRED_USER = "FORCE_PASSWORD_EXPIRED_USER";

    @Autowired
    private ResetPasswordService resetPasswordService;

    @RequestMapping(value="/force_password_change", method= GET)
    public String forcePasswordChangePage(Model model, HttpSession session) throws IOException {
        if(session.getAttribute(FORCE_PASSWORD_EXPIRED_USER) == null) {
            return "redirect:/login";
        }
        String email = ((UaaAuthentication)session.getAttribute(FORCE_PASSWORD_EXPIRED_USER)).getPrincipal().getEmail();
        model.addAttribute("email", email);
        return "force_password_change";
    }

    @RequestMapping(value="/force_password_change", method = POST)
    public String handleForcePasswordChange(Model model,
                                            @RequestParam("password")  String password,
                                            @RequestParam("password_confirmation") String passwordConfirmation,
                                            HttpServletRequest request,
                                            HttpServletResponse response,
                                            HttpSession session) throws IOException {
        if(session.getAttribute(FORCE_PASSWORD_EXPIRED_USER) == null) {
            return "redirect:" + request.getContextPath()+"/login";
        }
        UaaPrincipal principal = ((UaaAuthentication)session
            .getAttribute(FORCE_PASSWORD_EXPIRED_USER))
            .getPrincipal();

        String email = principal.getEmail();

        PasswordConfirmationValidation validation =
            new PasswordConfirmationValidation(email, password, passwordConfirmation);
        if(!validation.valid()) {
            return handleUnprocessableEntity(model, response, email);
        }

        resetPasswordService.resetUserPassword(principal.getId(), password);
        SecurityContextHolder.getContext().setAuthentication(((UaaAuthentication)session
            .getAttribute(FORCE_PASSWORD_EXPIRED_USER)));

        SavedRequest savedRequest = (SavedRequest) request.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        if(savedRequest != null) {
            return "redirect:" + savedRequest.getRedirectUrl();
        } else {
            return "redirect:/";
        }
    }

    public void setResetPasswordService(ResetPasswordService resetPasswordService) {
        this.resetPasswordService = resetPasswordService;
    }

    private String handleUnprocessableEntity(Model model, HttpServletResponse response, String email) {
        model.addAttribute("message_code", "form_error");
        model.addAttribute("email",  email);
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return "force_password_change";
    }
}
