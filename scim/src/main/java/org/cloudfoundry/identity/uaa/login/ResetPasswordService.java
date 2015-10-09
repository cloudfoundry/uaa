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

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;

import java.util.Map;

public interface ResetPasswordService {
    ForgotPasswordInfo forgotPassword(String email, String clientId, String redirectUri);

    ResetPasswordResponse resetPassword(String code, String password) throws InvalidPasswordException;

    public class ResetPasswordResponse {
        @JsonProperty("user")
        private ScimUser user;

        @JsonProperty("redirect_uri")
        private String redirectUri;

        public ResetPasswordResponse() {}

        public ResetPasswordResponse(ScimUser user, String redirectUri) {
            this.user = user;
            this.redirectUri = redirectUri;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public ScimUser getUser() {
            return user;
        }

        public void setUser(ScimUser user) {
            this.user = user;
        }
    }
}
