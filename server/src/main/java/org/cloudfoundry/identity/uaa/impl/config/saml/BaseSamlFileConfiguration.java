/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.impl.config.saml;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

public class BaseSamlFileConfiguration {

    private boolean signMetadata;
    private boolean signRequests;
    private String entityBaseUrl;
    private int metadataRefreshInterval;
    private long socketTimeout;
    private String defaultSignatureAlgorithm = "SHA1";
    private String defaultDigestMethod = "SHA1";

    @Value("${login.saml.signMetaData:true}")
    public BaseSamlFileConfiguration setSignMetadata(boolean signMetadata) {
        this.signMetadata = signMetadata;
        return this;
    }

    @Value("${login.saml.signRequest:true}")
    public BaseSamlFileConfiguration setSignRequests(boolean signRequests) {
        this.signRequests = signRequests;
        return this;
    }

    @Value("${login.entityBaseURL:http://localhost:8080/uaa}")
    public BaseSamlFileConfiguration setEntityBaseUrl(String entityBaseUrl) {
        this.entityBaseUrl = entityBaseUrl;
        return this;
    }

    @Value("${login.saml.metadataRefreshInterval:0}")
    public BaseSamlFileConfiguration setMetadataRefreshInterval(int metadataRefreshInterval) {
        this.metadataRefreshInterval = metadataRefreshInterval;
        return this;
    }

    @Value("${login.saml.socket.soTimeout:10000}")
    public BaseSamlFileConfiguration setSocketTimeout(long socketTimeout) {
        this.socketTimeout = socketTimeout;
        return this;
    }

    @Value("${login.saml.signatureAlgorithm:SHA1}")
    public BaseSamlFileConfiguration setDefaultSignatureAlgorithm(String defaultSignatureAlgorithm) {
        this.defaultSignatureAlgorithm = defaultSignatureAlgorithm;
        setDefaultDigestMethod(defaultSignatureAlgorithm);
        return this;
    }

    public BaseSamlFileConfiguration setDefaultDigestMethod(String defaultDigestMethod) {
        this.defaultDigestMethod = defaultDigestMethod;
        return this;
    }

    public boolean isSignMetadata() {
        return signMetadata;
    }

    public boolean isSignRequests() {
        return signRequests;
    }

    public String getEntityBaseUrl() {
        return entityBaseUrl;
    }

    public int getMetadataRefreshInterval() {
        return metadataRefreshInterval;
    }

    public long getSocketTimeout() {
        return socketTimeout;
    }

    public String getDefaultSignatureAlgorithm() {
        return defaultSignatureAlgorithm;
    }

    public String getDefaultDigestMethod() {
        return defaultDigestMethod;
    }

    public AlgorithmMethod getSignatureAlgorithm() {
        switch (getDefaultSignatureAlgorithm()) {
            case "SHA1":
                return AlgorithmMethod.RSA_SHA1;
            case "SHA256":
                return AlgorithmMethod.RSA_SHA256;
            case "SHA512":
                return AlgorithmMethod.RSA_SHA512;
        }
        return AlgorithmMethod.RSA_SHA256;
    }

    public DigestMethod getSignatureDigest() {
        switch (getDefaultSignatureAlgorithm()) {
            case "SHA1":
                return DigestMethod.SHA1;
            case "SHA256":
                return DigestMethod.SHA256;
            case "SHA512":
                return DigestMethod.SHA512;
        }
        return DigestMethod.SHA256;
    }

}
