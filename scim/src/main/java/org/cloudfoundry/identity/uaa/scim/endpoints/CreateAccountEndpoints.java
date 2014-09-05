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
import org.cloudfoundry.identity.uaa.rest.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;

@Controller
public class CreateAccountEndpoints {

    public static final String SIGNUP_REDIRECT_URL = "signup_redirect_url";

    private final ObjectMapper objectMapper;
    private final QueryableResourceManager<ClientDetails> clientDetailsService;
    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;

    public CreateAccountEndpoints(ObjectMapper objectMapper, QueryableResourceManager<ClientDetails> clientDetailsService, ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore) {
        this.objectMapper = objectMapper;
        this.clientDetailsService = clientDetailsService;
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
    }

    @RequestMapping(value = "/create_account", method = RequestMethod.POST)
    public ResponseEntity<Map<String,String>> changePassword(@RequestBody AccountCreation accountCreation) throws IOException {
        ResponseEntity<Map<String,String>> responseEntity;

        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(accountCreation.getCode());
        if (expiringCode != null) {
            try {
                Map<String, String> data = objectMapper.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
                String email = data.get("username");
                String clientId = data.get("client_id");
                ClientDetails clientDetails = clientDetailsService.retrieve(clientId);
                String redirectLocation = (String) clientDetails.getAdditionalInformation().get(SIGNUP_REDIRECT_URL);

                ScimUser user = scimUserProvisioning.createUser(newScimUser(email), accountCreation.getPassword());
                user = scimUserProvisioning.verifyUser(user.getId(), -1);

                Map<String, String> response = accountCreationResponse(user, redirectLocation);
                responseEntity = new ResponseEntity<>(response, CREATED);
            } catch (ScimResourceAlreadyExistsException e) {
                responseEntity = new ResponseEntity<>(CONFLICT);
            }
        } else {
            responseEntity = new ResponseEntity<>(BAD_REQUEST);
        }

        return responseEntity;
    }

    private Map<String, String> accountCreationResponse(ScimUser user, String redirectLocation) {
        Map<String, String> response = new HashMap<>();
        response.put("user_id", user.getId());
        response.put("username", user.getUserName());
        response.put("redirect_location", redirectLocation);
        return response;
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
}
