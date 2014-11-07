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

import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

public class UaaChangePasswordService implements ChangePasswordService {

    private final RestTemplate uaaTemplate;
    private final String uaaBaseUrl;

    public UaaChangePasswordService(RestTemplate authorizationTemplate, String uaaBaseUrl) {
        this.uaaTemplate = authorizationTemplate;
        this.uaaBaseUrl = uaaBaseUrl;
    }

    @Override
    public void changePassword(String username, String currentPassword, String newPassword) {
        Map<String, String> formData = new HashMap<String, String>();
        formData.put("username", username);
        formData.put("current_password", currentPassword);
        formData.put("new_password", newPassword);

        uaaTemplate.postForObject(uaaBaseUrl + "/password_change", formData, String.class);
    }
}
