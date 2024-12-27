/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URL;

public class VerificationResponse {
    @JsonProperty(value = "verify_link")
    private URL verifyLink;

    public URL getVerifyLink() {
        return verifyLink;
    }

    public void setVerifyLink(URL verifyLink) {
        this.verifyLink = verifyLink;
    }
}
