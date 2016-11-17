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

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import javax.servlet.http.HttpSession;

import java.io.IOException;

import static org.springframework.web.bind.annotation.RequestMethod.*;

@Controller
public class ForcePasswordChangeController {

    @RequestMapping(value="/force_password_change", method= GET)
    public String forcePasswordChangePage(Model model, HttpSession session) throws IOException {
        if(session.getAttribute("FORCE_PASSWORD_EXPIRED_USER") == null) {
            return "redirect:/login";
        }
        String email = ((UaaAuthentication)session.getAttribute("FORCE_PASSWORD_EXPIRED_USER")).getPrincipal().getEmail();
        model.addAttribute("email", email);
        return "force_password_change";
    }
}
