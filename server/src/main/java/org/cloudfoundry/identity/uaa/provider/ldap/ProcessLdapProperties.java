/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.security.LdapSocketFactory;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

public class ProcessLdapProperties {

    public static final String LDAP_SOCKET_FACTORY = "java.naming.ldap.factory.socket";
    public static final String SKIP_SSL_VERIFICATION_SOCKET_FACTORY = "org.apache.directory.api.util.DummySSLSocketFactory";
    public static final String EXPIRY_CHECKING_SOCKET_FACTORY = LdapSocketFactory.class.getName();

    private boolean disableSslVerification;
    private String baseUrl;

    public ProcessLdapProperties(String baseUrl, boolean disableSslVerification) {
        this.baseUrl = baseUrl;
        this.disableSslVerification = disableSslVerification;
    }

    public Map process(Map map) throws KeyManagementException, NoSuchAlgorithmException {
        Map result = new LinkedHashMap(map);
        if(isLdapsUrl()) {
            if (isDisableSslVerification()) {
                result.put(LDAP_SOCKET_FACTORY, SKIP_SSL_VERIFICATION_SOCKET_FACTORY);
            } else {
                result.put(LDAP_SOCKET_FACTORY, EXPIRY_CHECKING_SOCKET_FACTORY);
            }
        }
        return result;
    }

    public boolean isLdapsUrl() {
        return baseUrl!=null && baseUrl.startsWith("ldaps");
    }
    public boolean isDisableSslVerification() {
        return disableSslVerification;
    }

    public void setDisableSslVerification(boolean disableSslVerification) {
        this.disableSslVerification = disableSslVerification;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }
}
