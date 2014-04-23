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
package org.cloudfoundry.identity.uaa.scim.endpoints;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.OK;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.domain.ScimUser;
import org.codehaus.jackson.annotate.JsonProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.sql.Timestamp;
import java.util.List;

@Controller
public class PasswordResetEndpoints {

    public static final int PASSWORD_RESET_LIFETIME = 30 * 60 * 1000;
    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;

    public PasswordResetEndpoints(ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
    }

    @RequestMapping(value = "/password_resets", method = RequestMethod.POST)
    public ResponseEntity<String> resetPassword(@RequestBody String email) {
        List<ScimUser> results = scimUserProvisioning.query("email eq '" + email + "'");
        if (results.isEmpty()) {
            return new ResponseEntity<String>(BAD_REQUEST);
        }
        ScimUser scimUser = results.get(0);
        String code = expiringCodeStore.generateCode(scimUser.getId(), new Timestamp(System.currentTimeMillis() + PASSWORD_RESET_LIFETIME)).getCode();
        return new ResponseEntity<String>(code, CREATED);
    }

    @RequestMapping(value = "/password_change", method = RequestMethod.POST)
    public ResponseEntity<String> changePassword(@RequestBody PasswordChange passwordChange) {
        ResponseEntity<String> responseEntity;
        if (isCodeAuthenticatedChange(passwordChange)) {
            responseEntity = changePasswordCodeAuthenticated(passwordChange);
        } else if (isUsernamePasswordAuthenticatedChange(passwordChange)) {
            responseEntity = changePasswordUsernamePasswordAuthenticated(passwordChange);
        } else {
            responseEntity = new ResponseEntity<String>(BAD_REQUEST);
        }
        return responseEntity;
    }

    private boolean isUsernamePasswordAuthenticatedChange(PasswordChange passwordChange) {
        return passwordChange.getUsername() != null && passwordChange.getCurrentPassword() != null && passwordChange.getCode() == null;
    }

    private boolean isCodeAuthenticatedChange(PasswordChange passwordChange) {
        return passwordChange.getCode() != null && passwordChange.getCurrentPassword() == null && passwordChange.getUsername() == null;
    }

    private ResponseEntity<String> changePasswordUsernamePasswordAuthenticated(PasswordChange passwordChange) {
        List<ScimUser> results = scimUserProvisioning.query("userName eq '" + passwordChange.getUsername() + "'");
        if (results.isEmpty()) {
            return new ResponseEntity<String>(BAD_REQUEST);
        }
        String oldPassword = passwordChange.getCurrentPassword();
        ScimUser user = results.get(0);
        if (!scimUserProvisioning.changePassword(user.getId(), oldPassword, passwordChange.getNewPassword())) {
            return new ResponseEntity<String>(INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<String>(user.getUserName(), OK);
    }

    private ResponseEntity<String> changePasswordCodeAuthenticated(PasswordChange passwordChange) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(passwordChange.getCode());
        if (expiringCode == null) {
            return new ResponseEntity<String>(BAD_REQUEST);
        }
        String userId = expiringCode.getData();
        if (!scimUserProvisioning.changePassword(userId, null, passwordChange.getNewPassword())) {
            return new ResponseEntity<String>(INTERNAL_SERVER_ERROR);
        }
        ScimUser user = scimUserProvisioning.retrieve(userId);
        return new ResponseEntity<String>(user.getUserName(), OK);
    }

    private static class PasswordChange {
        @JsonProperty("username")
        private String username;

        @JsonProperty("code")
        private String code;

        @JsonProperty("current_password")
        private String currentPassword;

        @JsonProperty("new_password")
        private String newPassword;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }

        public String getCurrentPassword() {
            return currentPassword;
        }

        public void setCurrentPassword(String currentPassword) {
            this.currentPassword = currentPassword;
        }

        public String getNewPassword() {
            return newPassword;
        }

        public void setNewPassword(String newPassword) {
            this.newPassword = newPassword;
        }
    }
}
