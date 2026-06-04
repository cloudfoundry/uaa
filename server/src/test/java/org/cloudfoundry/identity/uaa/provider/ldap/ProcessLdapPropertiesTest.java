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

import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.DefaultTlsDirContextAuthenticationStrategy;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.ExternalTlsDirContextAuthenticationStrategy;
import org.junit.jupiter.api.Test;
import org.springframework.ldap.core.support.AbstractTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;
import org.springframework.test.util.ReflectionTestUtils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
    void authenticationStrategy() throws Exception {
        ProcessLdapProperties process = new ProcessLdapProperties("ldap://localhost:389", false, null);
        assertThat(process.getAuthenticationStrategy()).isExactlyInstanceOf(SimpleDirContextAuthenticationStrategy.class);
    }

    @Test
    void invalid_authenticationStrategy() {
        ProcessLdapProperties process = new ProcessLdapProperties("ldap://localhost:389", false, "asdadasda");
        assertThatThrownBy(process::getAuthenticationStrategy).asInstanceOf(InstanceOfAssertFactories.throwable(IllegalArgumentException.class));
    }

    @Test
    void authenticationStrategy_forTlsNone() throws Exception {
        // Case 1: LDAP_TLS_NONE - No TLS, returns SimpleDirContextAuthenticationStrategy (no hostname verification)
        ProcessLdapProperties tlsNone = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_NONE);
        assertThat(tlsNone.getAuthenticationStrategy()).isInstanceOf(SimpleDirContextAuthenticationStrategy.class);

        ProcessLdapProperties tlsNoneSkipSsl = new ProcessLdapProperties("ldap://localhost:389", true, LDAP_TLS_NONE);
        assertThat(tlsNoneSkipSsl.getAuthenticationStrategy()).isInstanceOf(SimpleDirContextAuthenticationStrategy.class);
    }

    @Test
    void authenticationStrategy_forTlsSimple() throws Exception {
        // Case 2: LDAP_TLS_SIMPLE with SSL verification enabled (default) 
        // Expected: Uses JDK default hostname verification (secure)
        ProcessLdapProperties tlsSimpleSecure = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_SIMPLE);
        var simpleSecureStrategy = (AbstractTlsDirContextAuthenticationStrategy) tlsSimpleSecure.getAuthenticationStrategy();
        assertThat(simpleSecureStrategy).isInstanceOf(DefaultTlsDirContextAuthenticationStrategy.class);
        assertThat(tlsSimpleSecure.isDisableSslVerification()).isFalse();
        HostnameVerifier actualVerifier = getHostnameVerifierFromStrategy(simpleSecureStrategy);
        assertThat(actualVerifier).isNotInstanceOf(NoopHostnameVerifier.class)
                .isSameAs(HttpsURLConnection.getDefaultHostnameVerifier());

        // Case 3: LDAP_TLS_SIMPLE with SSL verification disabled
        // Expected: Uses NoopHostnameVerifier
        ProcessLdapProperties tlsSimpleInsecure = new ProcessLdapProperties("ldap://localhost:389", true, LDAP_TLS_SIMPLE);
        var simpleInsecureStrategy = (AbstractTlsDirContextAuthenticationStrategy) tlsSimpleInsecure.getAuthenticationStrategy();
        assertThat(simpleInsecureStrategy).isInstanceOf(DefaultTlsDirContextAuthenticationStrategy.class);
        assertThat(tlsSimpleInsecure.isDisableSslVerification()).isTrue();
        assertThat(getHostnameVerifierFromStrategy(simpleInsecureStrategy)).isInstanceOf(NoopHostnameVerifier.class);
    }

    @Test
    void authenticationStrategy_forTlsExternal() throws Exception {
        // Case 4: LDAP_TLS_EXTERNAL with SSL verification enabled (default)
        // Expected: Uses JDK default hostname verification (secure)
        ProcessLdapProperties tlsExternalSecure = new ProcessLdapProperties("ldap://localhost:389", false, LDAP_TLS_EXTERNAL);
        var externalSecureStrategy = (AbstractTlsDirContextAuthenticationStrategy) tlsExternalSecure.getAuthenticationStrategy();
        assertThat(externalSecureStrategy).isInstanceOf(ExternalTlsDirContextAuthenticationStrategy.class);
        assertThat(tlsExternalSecure.isDisableSslVerification()).isFalse();
        HostnameVerifier actualVerifier = getHostnameVerifierFromStrategy(externalSecureStrategy);
        assertThat(actualVerifier).isNotInstanceOf(NoopHostnameVerifier.class)
                .isSameAs(HttpsURLConnection.getDefaultHostnameVerifier());

        // Case 5: LDAP_TLS_EXTERNAL with SSL verification disabled
        // Expected: Uses NoopHostnameVerifier
        ProcessLdapProperties tlsExternalInsecure = new ProcessLdapProperties("ldap://localhost:389", true, LDAP_TLS_EXTERNAL);
        var externalInsecureStrategy = (AbstractTlsDirContextAuthenticationStrategy) tlsExternalInsecure.getAuthenticationStrategy();
        assertThat(externalInsecureStrategy).isInstanceOf(ExternalTlsDirContextAuthenticationStrategy.class);
        assertThat(tlsExternalInsecure.isDisableSslVerification()).isTrue();
        assertThat(getHostnameVerifierFromStrategy(externalInsecureStrategy)).isInstanceOf(NoopHostnameVerifier.class);
    }
    
    /**
     * Helper method to extract the hostname verifier from an AbstractTlsDirContextAuthenticationStrategy
     * using ReflectionTestUtils since there's no public getter method.
     */
    private HostnameVerifier getHostnameVerifierFromStrategy(AbstractTlsDirContextAuthenticationStrategy strategy) {
        return (HostnameVerifier) ReflectionTestUtils.getField(strategy, "hostnameVerifier");
    }
}
