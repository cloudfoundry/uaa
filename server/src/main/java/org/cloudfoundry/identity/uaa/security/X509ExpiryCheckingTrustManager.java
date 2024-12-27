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

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class X509ExpiryCheckingTrustManager implements X509TrustManager {

    private X509TrustManager delegate;

    public X509ExpiryCheckingTrustManager() {
        try {
            TrustManagerFactory tmf;
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            X509TrustManager x509Tm = null;
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager manager) {
                    x509Tm = manager;
                    break;
                }
            }
            delegate = x509Tm;
        } catch (NoSuchAlgorithmException | KeyStoreException ignored) {
        }
    }

    protected void setDelegate(X509TrustManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        if (delegate == null) {
            throw new CertificateException();
        } else {
            delegate.checkClientTrusted(x509Certificates, s);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        if (delegate == null) {
            throw new CertificateException();
        } else {
            delegate.checkServerTrusted(x509Certificates, s);
        }
        for (X509Certificate certificate : x509Certificates) {
            certificate.checkValidity();
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        if (delegate != null) {
            return delegate.getAcceptedIssuers();
        }
        return new X509Certificate[0];
    }
}
