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
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;

import static org.springframework.web.bind.annotation.RequestMethod.*;

@Controller
public class ForcePasswordChangeController {

    public static final String FORCE_PASSWORD_EXPIRED_USER = "FORCE_PASSWORD_EXPIRED_USER";


    private ResetPasswordService resetPasswordService;

    public ForcePasswordChangeController(ResetPasswordService resetPasswordService) {
        this.resetPasswordService = resetPasswordService;
    }

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
    public void handleForcePasswordChange(Model model,
                                            @RequestParam("password")  String password,
                                            @RequestParam("password_conf") String passwordConf,
                                            HttpServletRequest request,
                                            HttpServletResponse response,
                                            HttpSession session) throws IOException {
        if(session.getAttribute(FORCE_PASSWORD_EXPIRED_USER) == null) {
           response.sendRedirect(request.getContextPath()+"/login");
           return;
        }
        UaaPrincipal principal = ((UaaAuthentication)session
            .getAttribute(FORCE_PASSWORD_EXPIRED_USER))
            .getPrincipal();

        String email = principal.getEmail();

        PasswordConfirmationValidation validation =
            new PasswordConfirmationValidation(email, password, passwordConf);
        if(!validation.valid()) {
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return;
        }

        resetPasswordService.resetUserPassword(principal.getId(), password);
        SecurityContextHolder.getContext().setAuthentication(((UaaAuthentication)session
            .getAttribute(FORCE_PASSWORD_EXPIRED_USER)));
        //TODO redirect to save request
    }
}
