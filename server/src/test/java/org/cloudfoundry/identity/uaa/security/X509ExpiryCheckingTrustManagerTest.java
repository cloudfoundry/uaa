/*
 *********************************************************************************
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

package org.cloudfoundry.identity.uaa.security;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

class X509ExpiryCheckingTrustManagerTest {

    @Test
    void checkServerTrusted_throwsExceptionWhenCertIsExpired() throws Exception {
        X509ExpiryCheckingTrustManager manager = new X509ExpiryCheckingTrustManager();
        X509TrustManager mockedDelegate = Mockito.mock(X509TrustManager.class);
        manager.setDelegate(mockedDelegate);
        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        X509Certificate[] x509Certificates = {certificate};

        doNothing().when(mockedDelegate).checkServerTrusted(x509Certificates, "string");
        doThrow(new CertificateExpiredException()).when(certificate).checkValidity();
        try {
            manager.checkServerTrusted(x509Certificates, "string");
            fail("");
        } catch (CertificateExpiredException e) {
            verify(mockedDelegate).checkServerTrusted(x509Certificates, "string");
            verify(certificate).checkValidity();
        }
    }

    @Test
    void checkClientTrusted_callsDelegate() throws Exception {
        X509ExpiryCheckingTrustManager manager = new X509ExpiryCheckingTrustManager();
        X509TrustManager mockedDelegate = Mockito.mock(X509TrustManager.class);
        manager.setDelegate(mockedDelegate);

        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        X509Certificate[] x509Certificates = {certificate};

        doNothing().when(mockedDelegate).checkClientTrusted(x509Certificates, "string");
        manager.checkClientTrusted(x509Certificates, "string");
        verify(mockedDelegate).checkClientTrusted(x509Certificates, "string");
    }

    @Test
    void checkAcceptedIssuers_callsDelegate() {
        X509ExpiryCheckingTrustManager manager = new X509ExpiryCheckingTrustManager();
        X509TrustManager mockedDelegate = Mockito.mock(X509TrustManager.class);
        manager.setDelegate(mockedDelegate);

        manager.getAcceptedIssuers();
        verify(mockedDelegate).getAcceptedIssuers();
    }
}
