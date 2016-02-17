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

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.util.StringUtils;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SamlConfig {
    private boolean requestSigned = true;
    private boolean wantAssertionSigned = false;
    private String certificate;
    private String privateKey;
    private String privateKeyPassword;

    @JsonIgnore
    private KeyWithCert keyCert;

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

    public void setCertificate(String certificate) throws CertificateException {
        this.certificate = certificate;

        if(StringUtils.hasText(privateKey)) {
            validateCert();
        }
    }

    public String getCertificate() {
        return certificate;
    }

    public void setPrivateKeyAndPassword(String privateKey, String privateKeyPassword) throws CertificateException {
        this.privateKey = privateKey;
        this.privateKeyPassword = privateKeyPassword;

        if(StringUtils.hasText(certificate)) {
            validateCert();
        }
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getPrivateKeyPassword() {
        return privateKeyPassword;
    }

    @JsonIgnore
    public java.security.KeyPair getKeyPair() {
        if(keyCert != null) { return keyCert.getPkey(); }
        else { return null; }
    }

    @JsonIgnore
    public X509Certificate getParsedCertificate() {
        if(keyCert != null) { return keyCert.getCert(); }
        else { return null; }
    }

    private void validateCert() throws CertificateException {
        keyCert = new KeyWithCert(privateKey, privateKeyPassword, certificate);
    }
}
