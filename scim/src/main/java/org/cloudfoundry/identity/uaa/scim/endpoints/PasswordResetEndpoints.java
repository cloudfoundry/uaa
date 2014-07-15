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
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeFailureEvent;
import org.cloudfoundry.identity.uaa.password.event.ResetPasswordRequestEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

@Controller
public class PasswordResetEndpoints implements ApplicationEventPublisherAware {

    public static final int PASSWORD_RESET_LIFETIME = 30 * 60 * 1000;
    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private final ObjectMapper objectMapper;
    private ApplicationEventPublisher publisher;

    public PasswordResetEndpoints(ObjectMapper objectMapper, ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore) {
        this.objectMapper = objectMapper;
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @RequestMapping(value = "/password_resets", method = RequestMethod.POST)
    public ResponseEntity<String> resetPassword(@RequestBody String email) throws IOException {
        String jsonEmail = objectMapper.writeValueAsString(email);
        List<ScimUser> results = scimUserProvisioning.query("email eq " + jsonEmail + " and origin eq \"" + Origin.UAA + "\"");
        if (results.isEmpty()) {
            results = scimUserProvisioning.query("email eq " + jsonEmail);
            if (results.isEmpty()) {
                return new ResponseEntity<>(BAD_REQUEST);
            } else {
                return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
            }
        }
        ScimUser scimUser = results.get(0);
        String code = expiringCodeStore.generateCode(scimUser.getId(), new Timestamp(System.currentTimeMillis() + PASSWORD_RESET_LIFETIME)).getCode();
        publish(new ResetPasswordRequestEvent(email, code, SecurityContextHolder.getContext().getAuthentication()));
        return new ResponseEntity<>(code, CREATED);
    }

    @RequestMapping(value = "/password_change", method = RequestMethod.POST)
    public ResponseEntity<String> changePassword(@RequestBody PasswordChange passwordChange) {
        ResponseEntity<String> responseEntity;
        if (isCodeAuthenticatedChange(passwordChange)) {
            responseEntity = changePasswordCodeAuthenticated(passwordChange);
        } else if (isUsernamePasswordAuthenticatedChange(passwordChange)) {
            responseEntity = changePasswordUsernamePasswordAuthenticated(passwordChange);
        } else {
            responseEntity = new ResponseEntity<>(BAD_REQUEST);
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
        List<ScimUser> results = scimUserProvisioning.query("userName eq \"" + passwordChange.getUsername() + "\"");
        if (results.isEmpty()) {
            return new ResponseEntity<>(BAD_REQUEST);
        }
        String oldPassword = passwordChange.getCurrentPassword();
        ScimUser user = results.get(0);
        try {
            scimUserProvisioning.changePassword(user.getId(), oldPassword, passwordChange.getNewPassword());
            publish(new PasswordChangeEvent("Password changed", getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            return new ResponseEntity<String>(user.getUserName(), OK);
        } catch (BadCredentialsException x) {
            publish(new PasswordChangeFailureEvent(x.getMessage(), getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            return new ResponseEntity<>(UNAUTHORIZED);
        } catch (ScimResourceNotFoundException x) {
            publish(new PasswordChangeFailureEvent(x.getMessage(), getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            return new ResponseEntity<>(NOT_FOUND);
        } catch (Exception x) {
            publish(new PasswordChangeFailureEvent(x.getMessage(), getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            return new ResponseEntity<>(INTERNAL_SERVER_ERROR);
        }
    }

    private ResponseEntity<String> changePasswordCodeAuthenticated(PasswordChange passwordChange) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(passwordChange.getCode());
        if (expiringCode == null) {
            return new ResponseEntity<>(BAD_REQUEST);
        }
        String userId = expiringCode.getData();
        ScimUser user = scimUserProvisioning.retrieve(userId);
        try {
            scimUserProvisioning.changePassword(userId, null, passwordChange.getNewPassword());
            publish(new PasswordChangeEvent("Password changed", getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            return new ResponseEntity<String>(user.getUserName(), OK);
        } catch (BadCredentialsException x) {
            publish(new PasswordChangeFailureEvent(x.getMessage(), getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            return new ResponseEntity<>(UNAUTHORIZED);
        } catch (ScimResourceNotFoundException x) {
            publish(new PasswordChangeFailureEvent(x.getMessage(), getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            return new ResponseEntity<>(NOT_FOUND);
        } catch (Exception x) {
            publish(new PasswordChangeFailureEvent(x.getMessage(), getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            return new ResponseEntity<>(INTERNAL_SERVER_ERROR);
        }
    }

    private UaaUser getUaaUser(ScimUser scimUser) {
        Date today = new Date();
        return new UaaUser(scimUser.getId(), scimUser.getUserName(), "N/A", scimUser.getPrimaryEmail(), null,
            scimUser.getGivenName(),
            scimUser.getFamilyName(), today, today,
            scimUser.getOrigin(), scimUser.getExternalId());
    }

    public static class PasswordChange {
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

    protected void publish(ApplicationEvent event) {
        if (publisher!=null) {
            publisher.publishEvent(event);
        }
    }
}
