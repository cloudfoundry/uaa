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

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.SecureRandom;

public class LdapSocketFactory extends BaseLdapSocketFactory {

    public LdapSocketFactory() {
        try {
            X509TrustManager trustManager = new X509ExpiryCheckingTrustManager();
            TrustManager[] tma = new TrustManager[]{trustManager};
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, tma, new SecureRandom());
            this.delegate = sc.getSocketFactory();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
