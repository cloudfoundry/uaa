/*******************************************************************************
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

package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordScore;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletResponse;

/**
 * Password quality check endpoint.
 * 
 * @author Luke Taylor
 */
//@Controller
public class PasswordCheckEndpoint {

    @RequestMapping(value = "/password/score", method = RequestMethod.POST)
    @ResponseBody
    public PasswordScore passwordScore(@RequestParam String password, @RequestParam(defaultValue = "") String userData,
                                       HttpServletResponse response) {
        response.addHeader("X-Cf-Warnings", "Endpoint+deprecated");
        return new PasswordScore(0,0);
    }
}
