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

package org.cloudfoundry.identity.uaa.config;

import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.HashMap;

/**
 * Created by pivotal on 11/11/15.
 */

public class KeyPair {
    private String verificationKey = new RandomValueStringGenerator().generate();
    private String signingKey = verificationKey;

    public KeyPair() {
    }

    public KeyPair(HashMap<String, String> keymap) {
        this(keymap.get("signingKey"), keymap.get("verificationKey"));
    }

    public KeyPair(String signingKey, String verificationKey) {
        this.signingKey = signingKey;
        this.verificationKey = verificationKey;
    }

    public String getSigningKey() {
        return signingKey;
    }

    public void setSigningKey(String signingKey) {
        this.signingKey = signingKey;
    }

    public String getVerificationKey() {
        return verificationKey;
    }

    public void setVerificationKey(String verificationKey) {
        this.verificationKey = verificationKey;
    }
}
