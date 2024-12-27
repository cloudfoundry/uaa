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
package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.scim.ScimUser;

public interface ResetPasswordService {
    void resetUserPassword(String userId, String password);

    ForgotPasswordInfo forgotPassword(String username, String clientId, String redirectUri);

    ResetPasswordResponse resetPassword(ExpiringCode code, String newPassword);

    class ResetPasswordResponse {
        @JsonProperty("user")
        private ScimUser user;

        @JsonProperty("redirect_uri")
        private String redirectUri;

        @JsonProperty("client_id")
        private String clientId;

        public ResetPasswordResponse() {
        }

        public ResetPasswordResponse(ScimUser user, String redirectUri, String clientId) {
            this.user = user;
            this.redirectUri = redirectUri;
            this.clientId = clientId;
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

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }
    }
}
