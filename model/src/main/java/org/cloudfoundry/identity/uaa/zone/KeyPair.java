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

package org.cloudfoundry.identity.uaa.zone;

import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.HashMap;
import java.util.UUID;

public class KeyPair {

    public static final String SIGNING_KEY = "signingKey";
    public static final String SIGNING_KEY_PASSWORD = "signingKeyPassword";
    public static final String VERIFICATION_KEY = "verificationKey";

    private UUID id;
    private String verificationKey = new RandomValueStringGenerator().generate();
    private String signingKey = verificationKey;
    private String signingKeyPassword;

    public KeyPair() {
    }

    public KeyPair(HashMap<String, String> keymap) {
        this(
            keymap.get(SIGNING_KEY),
            keymap.get(VERIFICATION_KEY),
            keymap.get(SIGNING_KEY_PASSWORD)
        );
    }

    public KeyPair(String signingKey, String verificationKey) {
        this(signingKey, verificationKey, null);
    }

    public KeyPair(String signingKey, String verificationKey, String signingKeyPassword) {
        this.signingKey = signingKey;
        this.verificationKey = verificationKey;
        this.signingKeyPassword = signingKeyPassword;
    }

    public UUID getId() { return id; }

    public void setId(UUID id) { this.id = id; }

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

    public String getSigningKeyPassword() {
        return signingKeyPassword;
    }

    public void setSigningKeyPassword(String signingKeyPassword) {
        this.signingKeyPassword = signingKeyPassword;
    }
}
