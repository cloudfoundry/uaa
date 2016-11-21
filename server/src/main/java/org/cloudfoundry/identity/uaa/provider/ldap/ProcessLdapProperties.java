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

import org.apache.directory.api.util.DummySSLSocketFactory;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.DefaultTlsDirContextAuthenticationStrategy;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.ExternalTlsDirContextAuthenticationStrategy;
import org.cloudfoundry.identity.uaa.security.LdapSocketFactory;
import org.springframework.ldap.core.support.AbstractTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;

import javax.net.ssl.SSLSocketFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.util.StringUtils.hasText;

public class ProcessLdapProperties {

    public static final String LDAP_SOCKET_FACTORY = "java.naming.ldap.factory.socket";
    public static final String LDAP_SSL_SOCKET_FACTORY = "org.cloudfoundry.identity.ldap.ssl.factory.socket";
    public static final String SKIP_SSL_VERIFICATION_SOCKET_FACTORY = DummySSLSocketFactory.class.getName();
    public static final String EXPIRY_CHECKING_SOCKET_FACTORY = LdapSocketFactory.class.getName();
    public static final String NONE = "none";
    public static final String SIMPLE = "simple";
    public static final String EXTERNAL = "external";

    private boolean disableSslVerification;
    private String baseUrl;
    private String tlsConfig = NONE;

    public ProcessLdapProperties(String baseUrl,
                                 boolean disableSslVerification,
                                 String tlsConfig) {
        this.baseUrl = baseUrl;
        this.disableSslVerification = disableSslVerification;
        this.tlsConfig = tlsConfig;
    }

    public Map process(Map map) throws KeyManagementException, NoSuchAlgorithmException {
        Map result = new LinkedHashMap(map);
        if (isDisableSslVerification()) {
            result.put(LDAP_SSL_SOCKET_FACTORY, SKIP_SSL_VERIFICATION_SOCKET_FACTORY);
        } else {
            result.put(LDAP_SSL_SOCKET_FACTORY, EXPIRY_CHECKING_SOCKET_FACTORY);
        }

        if (isLdapsUrl()) {
            result.put(LDAP_SOCKET_FACTORY, result.get(LDAP_SSL_SOCKET_FACTORY));
        }
        return result;
    }

    public boolean isLdapsUrl() {
        return baseUrl != null && baseUrl.startsWith("ldaps");
    }

    public boolean isDisableSslVerification() {
        return disableSslVerification;
    }

    public SSLSocketFactory getSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException, IllegalAccessException, InstantiationException, ClassNotFoundException {
        Class<?> clazz = Class.forName((String) (process(new HashMap()).get(LDAP_SSL_SOCKET_FACTORY)), true, ProcessLdapProperties.class.getClassLoader());
        return (SSLSocketFactory) clazz.newInstance();
    }

    public void setDisableSslVerification(boolean disableSslVerification) {
        this.disableSslVerification = disableSslVerification;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }


    public DirContextAuthenticationStrategy getAuthenticationStrategy() throws ClassNotFoundException, NoSuchAlgorithmException, IllegalAccessException, InstantiationException, KeyManagementException {
        if (!hasText(tlsConfig)) {
            tlsConfig = NONE;
        }
        AbstractTlsDirContextAuthenticationStrategy tlsStrategy;
        switch (tlsConfig) {
            case NONE:
                return new SimpleDirContextAuthenticationStrategy();
            case SIMPLE:
                tlsStrategy = new DefaultTlsDirContextAuthenticationStrategy();
                break;
            case EXTERNAL:
                tlsStrategy = new ExternalTlsDirContextAuthenticationStrategy();
                break;
            default:
                throw new IllegalArgumentException(tlsConfig);
        }
        tlsStrategy.setHostnameVerifier(new AllowAllHostnameVerifier());
        tlsStrategy.setSslSocketFactory(getSSLSocketFactory());
        return tlsStrategy;
    }
}
