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

import com.fasterxml.jackson.annotation.JsonProperty;
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
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils.JsonUtilException;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Controller
public class PasswordResetEndpoints implements ApplicationEventPublisherAware {

    public static final int PASSWORD_RESET_LIFETIME = 30 * 60 * 1000;
    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private ApplicationEventPublisher publisher;

    public PasswordResetEndpoints(ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @RequestMapping(value = "/password_resets", method = RequestMethod.POST)
    public ResponseEntity<Map<String,String>> resetPassword(@RequestBody String email) throws IOException {
        String jsonEmail = JsonUtils.writeValueAsString(email);
        Map<String,String> response = new HashMap<>();
        List<ScimUser> results = scimUserProvisioning.query("userName eq " + jsonEmail + " and origin eq \"" + Origin.UAA + "\"");
        if (results.isEmpty()) {
            results = scimUserProvisioning.query("userName eq " + jsonEmail);
            if (results.isEmpty()) {
                return new ResponseEntity<>(NOT_FOUND);
            } else {
                response.put("user_id", results.get(0).getId());
                return new ResponseEntity<>(response, CONFLICT);
            }
        }
        ScimUser scimUser = results.get(0);
        PasswordChange change = new PasswordChange(scimUser.getId(), scimUser.getUserName());
        String code = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + PASSWORD_RESET_LIFETIME)).getCode();
        publish(new ResetPasswordRequestEvent(email, code, SecurityContextHolder.getContext().getAuthentication()));
        response.put("code", code);
        response.put("user_id", scimUser.getId());
        return new ResponseEntity<>(response, CREATED);
    }

    @RequestMapping(value = "/password_change", method = RequestMethod.POST)
    public ResponseEntity<Map<String,String>> changePassword(@RequestBody PasswordChange passwordChange) {
        ResponseEntity<Map<String,String>> responseEntity;
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

    private ResponseEntity<Map<String,String>> changePasswordUsernamePasswordAuthenticated(PasswordChange passwordChange) {
        List<ScimUser> results = scimUserProvisioning.query("userName eq \"" + passwordChange.getUsername() + "\"");
        if (results.isEmpty()) {
            return new ResponseEntity<>(BAD_REQUEST);
        }
        String oldPassword = passwordChange.getCurrentPassword();
        ScimUser user = results.get(0);
        try {
            scimUserProvisioning.changePassword(user.getId(), oldPassword, passwordChange.getNewPassword());
            publish(new PasswordChangeEvent("Password changed", getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            Map<String,String> userInfo = new HashMap<>();
            userInfo.put("user_id", user.getId());
            userInfo.put("username", user.getUserName());
            return new ResponseEntity<>(userInfo, OK);
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

    protected ResponseEntity<Map<String,String>> changePasswordCodeAuthenticated(PasswordChange passwordChange) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(passwordChange.getCode());
        if (expiringCode == null) {
            return new ResponseEntity<>(BAD_REQUEST);
        }
        String userId;
        String userName = null;
        try {
            PasswordChange change = JsonUtils.readValue(expiringCode.getData(), PasswordChange.class);
            userId = change.getUserId();
            userName = change.getUsername();
        } catch (JsonUtilException x) {
            userId = expiringCode.getData();
        }
        ScimUser user = scimUserProvisioning.retrieve(userId);
        Map<String,String> userInfo = new HashMap<>();
        try {
            if (isUserModified(user, expiringCode.getExpiresAt(), userName)) {
                return new ResponseEntity<>(BAD_REQUEST);
            }
            if (!user.isVerified()) {
                scimUserProvisioning.verifyUser(userId, -1);
            }
            scimUserProvisioning.changePassword(userId, null, passwordChange.getNewPassword());
            publish(new PasswordChangeEvent("Password changed", getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            userInfo.put("user_id", user.getId());
            userInfo.put("username", user.getUserName());
            userInfo.put("email", user.getPrimaryEmail());
            return new ResponseEntity<>(userInfo, OK);
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

    protected boolean isUserModified(ScimUser user, Timestamp expiresAt, String userName) {
        if (userName!=null) {
            return ! userName.equals(user.getUserName());
        }
        //left over from when all we stored in the code was the user ID
        //here we will check the timestamp
        //TODO - REMOVE THIS IN FUTURE RELEASE, ALL LINKS HAVE BEEN EXPIRED (except test created ones)
        long codeCreated = expiresAt.getTime() - PASSWORD_RESET_LIFETIME;
        long userModified = user.getMeta().getLastModified().getTime();
        return (userModified > codeCreated);
    }

    protected UaaUser getUaaUser(ScimUser scimUser) {
        Date today = new Date();
        return new UaaUser(scimUser.getId(), scimUser.getUserName(), "N/A", scimUser.getPrimaryEmail(), null,
            scimUser.getGivenName(),
            scimUser.getFamilyName(), today, today,
            scimUser.getOrigin(), scimUser.getExternalId(), scimUser.isVerified(), scimUser.getZoneId(), scimUser.getSalt());
    }

    public static class PasswordChange {
        public PasswordChange() {}

        public PasswordChange(String userId, String username) {
            this.userId = userId;
            this.username = username;
        }

        @JsonProperty("user_id")
        private String userId;

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

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }
    }

    protected void publish(ApplicationEvent event) {
        if (publisher!=null) {
            publisher.publishEvent(event);
        }
    }
}
