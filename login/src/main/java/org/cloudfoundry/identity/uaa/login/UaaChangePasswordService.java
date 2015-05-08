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

import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

public class UaaChangePasswordService implements ChangePasswordService {

    private final PasswordResetEndpoints passwordResetEndpoints;

    public UaaChangePasswordService(PasswordResetEndpoints passwordResetEndpoints) {
        this.passwordResetEndpoints= passwordResetEndpoints;
    }

    @Override
    public void changePassword(String username, String currentPassword, String newPassword) {
        PasswordResetEndpoints.PasswordChange change = new PasswordResetEndpoints.PasswordChange();
        change.setUsername(username);
        change.setCurrentPassword(currentPassword);
        change.setNewPassword(newPassword);
        ResponseEntity<Map<String,String>> response = passwordResetEndpoints.changePassword(change);
        if (! response.getStatusCode().is2xxSuccessful()) {
            //throw an error
            throw new BadCredentialsException(username);
        }
    }
}
