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
import org.junit.jupiter.api.Test;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_EXTERNAL;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_NONE;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_SIMPLE;
import static org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties.LDAP_SOCKET_FACTORY;
import static org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties.LDAP_SSL_SOCKET_FACTORY;

class ProcessLdapPropertiesTest {

    @Test
    void process() throws Exception {
        Map<String, String> properties = new HashMap<>();
        ProcessLdapProperties process = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_NONE);
        assertThat(process.process(properties)).doesNotContainKey(LDAP_SOCKET_FACTORY)
                .containsEntry(LDAP_SSL_SOCKET_FACTORY, ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY);
        assertThat(process.getSSLSocketFactory().getClass().getName()).isEqualTo(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY);
        process.setDisableSslVerification(true);
        assertThat(process.process(properties)).doesNotContainKey(LDAP_SOCKET_FACTORY);
        process.setBaseUrl("ldaps://localhost:636");
        assertThat(process.process(properties)).containsEntry(LDAP_SOCKET_FACTORY, ProcessLdapProperties.SKIP_SSL_VERIFICATION_SOCKET_FACTORY)
                .containsEntry(LDAP_SSL_SOCKET_FACTORY, ProcessLdapProperties.SKIP_SSL_VERIFICATION_SOCKET_FACTORY);
        assertThat(process.getSSLSocketFactory().getClass().getName()).isEqualTo(ProcessLdapProperties.SKIP_SSL_VERIFICATION_SOCKET_FACTORY);
    }

    @Test
    void process_whenSslValidationIsEnabled() throws Exception {
        Map<String, String> properties = new HashMap<>();
        ProcessLdapProperties process = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_NONE);
        assertThat(process.process(properties)).doesNotContainKey(LDAP_SOCKET_FACTORY)
                .containsEntry(LDAP_SSL_SOCKET_FACTORY, ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY);
        assertThat(process.getSSLSocketFactory().getClass().getName()).isEqualTo(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY);
        process.setDisableSslVerification(false);
        assertThat(process.process(properties)).doesNotContainKey(LDAP_SOCKET_FACTORY)
                .containsEntry(LDAP_SSL_SOCKET_FACTORY, ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY);
        assertThat(process.getSSLSocketFactory().getClass().getName()).isEqualTo(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY);
        process.setBaseUrl("ldaps://localhost:636");
        assertThat(process.process(properties)).containsEntry(LDAP_SOCKET_FACTORY, ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY)
                .containsEntry(LDAP_SSL_SOCKET_FACTORY, ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY);
        assertThat(process.getSSLSocketFactory().getClass().getName()).isEqualTo(ProcessLdapProperties.EXPIRY_CHECKING_SOCKET_FACTORY);
    }

    @Test
    void authentication_strategy() throws Exception {
        ProcessLdapProperties process = new ProcessLdapProperties("ldap://localhost:389", false, null);
        assertThat(process.getAuthenticationStrategy().getClass()).isEqualTo(SimpleDirContextAuthenticationStrategy.class);
        process = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_NONE);
        assertThat(process.getAuthenticationStrategy().getClass()).isEqualTo(SimpleDirContextAuthenticationStrategy.class);
        process = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_SIMPLE);
        assertThat(process.getAuthenticationStrategy().getClass()).isEqualTo(DefaultTlsDirContextAuthenticationStrategy.class);
        process = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_EXTERNAL);
        assertThat(process.getAuthenticationStrategy().getClass()).isEqualTo(ExternalTlsDirContextAuthenticationStrategy.class);
    }

    @Test
    void invalid_authentication_strategy() {
        ProcessLdapProperties process = new ProcessLdapProperties("ldap://localhost:389", false, "asdadasda");
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(process::getAuthenticationStrategy);
    }
}
