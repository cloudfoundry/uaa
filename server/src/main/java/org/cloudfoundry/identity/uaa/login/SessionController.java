/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SessionController {

    @RequestMapping("/session")
    public String session(Model model, @RequestParam String clientId, @RequestParam String messageOrigin) {
        // We need to maintain this version of the session page to continue compatibility with the
        // original version of uaa-singular.
        model.addAttribute("clientId", clientId);
        model.addAttribute("messageOrigin", messageOrigin);
        return "session";
    }

    @RequestMapping("/session_management")
    public String sessionManagement(Model model, @RequestParam String clientId, @RequestParam String messageOrigin) {
        model.addAttribute("clientId", clientId);
        model.addAttribute("messageOrigin", messageOrigin);
        return "session_management";
    }
}
