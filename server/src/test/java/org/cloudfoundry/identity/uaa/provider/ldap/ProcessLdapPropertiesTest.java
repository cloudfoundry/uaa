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

package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.provider.ldap.extension.DefaultTlsDirContextAuthenticationStrategy;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.ExternalTlsDirContextAuthenticationStrategy;
import org.junit.Test;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;

import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.*;
import static org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties.LDAP_SOCKET_FACTORY;
import static org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties.LDAP_SSL_SOCKET_FACTORY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class ProcessLdapPropertiesTest {

    @Test
    public void testProcess() throws Exception {
        Map<String,String> properties = new HashMap<>();
        ProcessLdapProperties process = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_NONE);
        assertNull(process.process(properties).get(LDAP_SOCKET_FACTORY));
        assertEquals(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY, process.process(properties).get(LDAP_SSL_SOCKET_FACTORY));
        assertEquals(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY, process.getSSLSocketFactory().getClass().getName());
        process.setDisableSslVerification(true);
        assertNull(process.process(properties).get(LDAP_SOCKET_FACTORY));
        process.setBaseUrl("ldaps://localhost:636");
        assertEquals(ProcessLdapProperties.SKIP_SSL_VERIFICATION_SOCKET_FACTORY, process.process(properties).get(LDAP_SOCKET_FACTORY));
        assertEquals(ProcessLdapProperties.SKIP_SSL_VERIFICATION_SOCKET_FACTORY, process.process(properties).get(LDAP_SSL_SOCKET_FACTORY));
        assertEquals(ProcessLdapProperties.SKIP_SSL_VERIFICATION_SOCKET_FACTORY, process.getSSLSocketFactory().getClass().getName());

    }

    @Test
    public void process_whenSslValidationIsEnabled() throws Exception {
        Map<String,String> properties = new HashMap<>();
        ProcessLdapProperties process = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_NONE);
        assertNull(process.process(properties).get(LDAP_SOCKET_FACTORY));
        assertEquals(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY, process.process(properties).get(LDAP_SSL_SOCKET_FACTORY));
        assertEquals(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY, process.getSSLSocketFactory().getClass().getName());
        process.setDisableSslVerification(false);
        assertNull(process.process(properties).get(LDAP_SOCKET_FACTORY));
        assertEquals(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY, process.process(properties).get(LDAP_SSL_SOCKET_FACTORY));
        assertEquals(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY, process.getSSLSocketFactory().getClass().getName());
        process.setBaseUrl("ldaps://localhost:636");
        assertEquals(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY, process.process(properties).get(LDAP_SOCKET_FACTORY));
        assertEquals(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY, process.process(properties).get(LDAP_SSL_SOCKET_FACTORY));
        assertEquals(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY, process.getSSLSocketFactory().getClass().getName());
    }

    @Test
    public void test_authentication_strategy() throws Exception {
        ProcessLdapProperties process = new ProcessLdapProperties("ldap://localhost:389", false, null);
        assertEquals(SimpleDirContextAuthenticationStrategy.class, process.getAuthenticationStrategy().getClass());
        process = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_NONE);
        assertEquals(SimpleDirContextAuthenticationStrategy.class, process.getAuthenticationStrategy().getClass());
        process = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_SIMPLE);
        assertEquals(DefaultTlsDirContextAuthenticationStrategy.class, process.getAuthenticationStrategy().getClass());
        process = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_EXTERNAL);
        assertEquals(ExternalTlsDirContextAuthenticationStrategy.class, process.getAuthenticationStrategy().getClass());
    }

    @Test(expected = IllegalArgumentException.class)
    public void invalid_authentication_strategy() throws Exception {
        ProcessLdapProperties process = new ProcessLdapProperties("ldap://localhost:389", false, "asdadasda");
        process.getAuthenticationStrategy();
    }

}
