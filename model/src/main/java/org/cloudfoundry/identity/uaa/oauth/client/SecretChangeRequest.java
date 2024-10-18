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
package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.UPDATE;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretChangeRequest {

    public enum ChangeMode {
        UPDATE,
        ADD,
        DELETE
    }

    private String oldSecret;
    private String secret;
    private String clientId;
    private ChangeMode changeMode = UPDATE;

    public SecretChangeRequest() {
    }

    public SecretChangeRequest(String clientId, String oldSecret, String secret) {
        this.oldSecret = oldSecret;
        this.secret = secret;
        this.clientId = clientId;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getOldSecret() {
        return oldSecret;
    }

    public void setOldSecret(String old) {
        this.oldSecret = old;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public ChangeMode getChangeMode() {
        return changeMode;
    }

    public void setChangeMode(ChangeMode changeMode) {
        this.changeMode = changeMode;
    }
}
