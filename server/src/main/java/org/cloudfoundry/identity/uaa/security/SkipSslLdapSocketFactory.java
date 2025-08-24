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

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.SocketFactory;

public class SkipSslLdapSocketFactory extends BaseLdapSocketFactory {

    private static SocketFactory instance;

    public static SocketFactory getDefault() {
        if (instance == null) {
            instance = new SkipSslLdapSocketFactory();
        }

        return instance;
    }

    public SkipSslLdapSocketFactory() {
        try {
            TrustManager trustManager = new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                    // ignore
                }

                public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                    // ignore
                }
            };

            TrustManager[] tma = new TrustManager[]{trustManager};
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, tma, new SecureRandom());
            this.delegate = sc.getSocketFactory();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
