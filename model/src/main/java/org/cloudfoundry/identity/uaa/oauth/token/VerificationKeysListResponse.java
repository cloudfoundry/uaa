/*
 * ******************************************************************************
 *       Cloud Foundry Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *       This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *       You may not use this product except in compliance with the License.
 *
 *       This product includes a number of subcomponents with
 *       separate copyright notices and license terms. Your use of these
 *       subcomponents is subject to the terms and conditions of the
 *       subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

import java.util.List;

/**
 * Created by pivotal on 11/18/15.
 */
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE, setterVisibility = JsonAutoDetect.Visibility.NONE)
public class VerificationKeysListResponse {
    private List<VerificationKeyResponse> keys;

    public List<VerificationKeyResponse> getKeys() {
        return keys;
    }

    public void setKeys(List<VerificationKeyResponse> keys) {
        this.keys = keys;
    }
}
