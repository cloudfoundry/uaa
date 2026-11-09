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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Default-trust manager that also rejects expired certificates. Extends
 * {@link X509ExtendedTrustManager} so the delegate still performs endpoint identification.
 */
public class X509ExpiryCheckingTrustManager extends X509ExtendedTrustManager {

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
        } catch (NoSuchAlgorithmException | KeyStoreException _) {
            // ignore
        }
    }

    protected void setDelegate(X509TrustManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        requireDelegate().checkClientTrusted(x509Certificates, s);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        X509TrustManager tm = requireDelegate();
        if (tm instanceof X509ExtendedTrustManager extended) {
            extended.checkClientTrusted(x509Certificates, s, socket);
        } else {
            tm.checkClientTrusted(x509Certificates, s);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine engine) throws CertificateException {
        X509TrustManager tm = requireDelegate();
        if (tm instanceof X509ExtendedTrustManager extended) {
            extended.checkClientTrusted(x509Certificates, s, engine);
        } else {
            tm.checkClientTrusted(x509Certificates, s);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        requireDelegate().checkServerTrusted(x509Certificates, s);
        checkValidity(x509Certificates);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        X509TrustManager tm = requireDelegate();
        if (tm instanceof X509ExtendedTrustManager extended) {
            extended.checkServerTrusted(x509Certificates, s, socket);
        } else {
            tm.checkServerTrusted(x509Certificates, s);
        }
        checkValidity(x509Certificates);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine engine) throws CertificateException {
        X509TrustManager tm = requireDelegate();
        if (tm instanceof X509ExtendedTrustManager extended) {
            extended.checkServerTrusted(x509Certificates, s, engine);
        } else {
            tm.checkServerTrusted(x509Certificates, s);
        }
        checkValidity(x509Certificates);
    }

    private X509TrustManager requireDelegate() throws CertificateException {
        if (delegate == null) {
            throw new CertificateException();
        }
        return delegate;
    }

    private static void checkValidity(X509Certificate[] x509Certificates) throws CertificateException {
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
