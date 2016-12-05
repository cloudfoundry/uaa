/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

public class SamlConfig {
    private boolean assertionSigned = true;
    private boolean requestSigned = true;
    private boolean wantAssertionSigned = true;
    private boolean wantAuthnRequestSigned = false;
    private int assertionTimeToLiveSeconds = 600;
    private String certificate;
    private String privateKey;
    private String privateKeyPassword;

    public boolean isAssertionSigned() {
        return assertionSigned;
    }

    public void setAssertionSigned(boolean assertionSigned) {
        this.assertionSigned = assertionSigned;
    }

    public boolean isRequestSigned() {
        return requestSigned;
    }

    public void setRequestSigned(boolean requestSigned) {
        this.requestSigned = requestSigned;
    }

    public boolean isWantAssertionSigned() {
        return wantAssertionSigned;
    }

    public void setWantAssertionSigned(boolean wantAssertionSigned) {
        this.wantAssertionSigned = wantAssertionSigned;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public boolean isWantAuthnRequestSigned() {
        return wantAuthnRequestSigned;
    }

    public void setWantAuthnRequestSigned(boolean wantAuthnRequestSigned) {
        this.wantAuthnRequestSigned = wantAuthnRequestSigned;
    }

    public int getAssertionTimeToLiveSeconds() {
        return assertionTimeToLiveSeconds;
    }

    public void setAssertionTimeToLiveSeconds(int assertionTimeToLiveSeconds) {
        this.assertionTimeToLiveSeconds = assertionTimeToLiveSeconds;
    }

    public String getCertificate() {
        return certificate;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getPrivateKeyPassword() {
        return privateKeyPassword;
    }

    public void setPrivateKeyPassword(String privateKeyPassword) {
        this.privateKeyPassword = privateKeyPassword;
    }
}
