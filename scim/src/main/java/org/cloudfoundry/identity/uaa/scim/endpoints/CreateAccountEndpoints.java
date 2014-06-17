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

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.codehaus.jackson.annotate.JsonProperty;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.Arrays;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;

@Controller
public class CreateAccountEndpoints implements ApplicationEventPublisherAware {

    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private ApplicationEventPublisher publisher;

    public CreateAccountEndpoints(ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @RequestMapping(value = "/create_account", method = RequestMethod.POST)
    public ResponseEntity<String> changePassword(@RequestBody AccountCreation accountCreation) {
        ResponseEntity<String> responseEntity;

        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(accountCreation.getCode());
        if (expiringCode != null) {
            try {
                String email = expiringCode.getData();
                scimUserProvisioning.createUser(newScimUser(email), accountCreation.getPassword());
                responseEntity = new ResponseEntity<>(CREATED);
            } catch (ScimResourceAlreadyExistsException e) {
                responseEntity = new ResponseEntity<>(CONFLICT);
            }
        } else {
            responseEntity = new ResponseEntity<>(BAD_REQUEST);
        }

        return responseEntity;
    }

    private ScimUser newScimUser(String emailAddress) {
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(emailAddress);
        ScimUser.Email email = new ScimUser.Email();
        email.setPrimary(true);
        email.setValue(emailAddress);
        scimUser.setEmails(Arrays.asList(email));
        scimUser.setOrigin(Origin.UAA);
        return scimUser;
    }

    private static class AccountCreation {
        @JsonProperty("code")
        private String code;

        @JsonProperty("password")
        private String password;

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    protected void publish(ApplicationEvent event) {
        if (publisher!=null) {
            publisher.publishEvent(event);
        }
    }
}
