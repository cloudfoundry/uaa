/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock.ldap;


import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.ldap.server.ApacheDsSSLContainer;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.FileSystemUtils;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class LdapCertificateMockMvcTests extends InjectedMockContextTest {
    public static final int LDAP_VALID_LDAP_PORT = 33390;
    public static final int LDAP_EXPIRED_LDAP_PORT = LDAP_VALID_LDAP_PORT + 1;
    public static final int LDAP_VALID_LDAPS_PORT = 33637;
    public static final int LDAP_EXPIRED_LDAPS_PORT = LDAP_VALID_LDAPS_PORT + 1;
    private static File LDAP_ROOT_DIRECTORY_EXPIRED;

    private static File LDAP_ROOT_DIRECTORY_VALID;
    private static ApacheDsSSLContainer validLdapCertServer;
    private static ApacheDsSSLContainer expiredLdapCertServer;
    private MockMvcUtils.IdentityZoneCreationResult trustedCertZone;
    private MockMvcUtils.IdentityZoneCreationResult trustedButExpiredCertZone;

    private static final AtomicBoolean started = new AtomicBoolean(false);

    @BeforeClass
    public static void startLdapsServers() throws Exception {
        if (started.compareAndSet(false, true)) {
            File expiredKeystore = new File(System.getProperty("java.io.tmpdir"), "expired-self-signed-ldap-cert.jks");
            File validKeystore = new File(System.getProperty("java.io.tmpdir"), "valid-self-signed-ldap-cert.jks");
            assertTrue("Did you run scripts/travis/install-ldap-certs.sh?\nFile:" + expiredKeystore.getAbsolutePath() + " should exist.", expiredKeystore.exists() && expiredKeystore.canRead());
            assertTrue("Did you run scripts/travis/install-ldap-certs.sh?\nFile:" + validKeystore.getAbsolutePath() + " should exist.", validKeystore.exists() && validKeystore.canRead());
            RandomValueStringGenerator generator = new RandomValueStringGenerator();
            LDAP_ROOT_DIRECTORY_VALID = new File(System.getProperty("java.io.tmpdir"), generator.generate());
            LDAP_ROOT_DIRECTORY_EXPIRED = new File(System.getProperty("java.io.tmpdir"), generator.generate());
            validLdapCertServer = new ApacheDsSSLContainer("dc=test,dc=com", new Resource[]{new ClassPathResource("ldap_init_apacheds.ldif"), new ClassPathResource("ldap_init.ldif")})
                .setWorkingDirectory(LDAP_ROOT_DIRECTORY_VALID)
                .setPort(LDAP_VALID_LDAP_PORT)
                .setSslPort(LDAP_VALID_LDAPS_PORT)
                .afterPropertiesSet(validKeystore);

            expiredLdapCertServer = new ApacheDsSSLContainer("dc=test,dc=com", new Resource[]{new ClassPathResource("ldap_init_apacheds.ldif"), new ClassPathResource("ldap_init.ldif")})
                .setWorkingDirectory(LDAP_ROOT_DIRECTORY_EXPIRED)
                .setPort(LDAP_EXPIRED_LDAP_PORT)
                .setSslPort(LDAP_EXPIRED_LDAPS_PORT)
                .afterPropertiesSet(expiredKeystore);
        }

    }

    @AfterClass
    public static void stopLdapsServers() throws Exception {
        if (started.compareAndSet(true,false)) {
            ofNullable(validLdapCertServer).ifPresent(s -> s.stop());
            ofNullable(expiredLdapCertServer).ifPresent(s -> s.stop());
            ofNullable(LDAP_ROOT_DIRECTORY_VALID).ifPresent(d -> FileSystemUtils.deleteRecursively(d));
        }
    }


    @Before
    public void createzones() throws Exception {
        trustedCertZone = utils().createOtherIdentityZoneAndReturnResult(
            gen.generate(),
            getMockMvc(),
            getWebApplicationContext(),
            null);

        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "ldaps://localhost:"+LDAP_VALID_LDAPS_PORT,
            "cn=admin,ou=Users,dc=test,dc=com",
            "adminsecret",
            "dc=test,dc=com",
            "cn={0}",
            "ou=scopes,dc=test,dc=com",
            "member={0}",
            "mail",
            null,
            false,
            true,
            true,
            10,
            false
        );

        MockMvcUtils.createIdentityProvider(getMockMvc(), trustedCertZone, OriginKeys.LDAP, definition);
        trustedButExpiredCertZone = utils().createOtherIdentityZoneAndReturnResult(
            gen.generate(),
            getMockMvc(),
            getWebApplicationContext(),
            null);
        definition.setBaseUrl("ldaps://localhost:"+LDAP_EXPIRED_LDAPS_PORT);
        MockMvcUtils.createIdentityProvider(getMockMvc(), trustedButExpiredCertZone, OriginKeys.LDAP, definition);

    }

    @Test
    public void trusted_server_certificate() throws Exception {
        getMockMvc().perform(post("/login.do").accept(TEXT_HTML_VALUE)
                            .with(cookieCsrf())
                            .with(new SetServerNameRequestPostProcessor(trustedCertZone.getIdentityZone().getSubdomain()+".localhost"))
                            .param("username", "marissa2")
                            .param("password", LDAP))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andExpect(authenticated());
    }

    @Test
    public void trusted_but_expired_server_certificate() throws Exception {
        getMockMvc().perform(post("/login.do").accept(TEXT_HTML_VALUE)
                                 .with(cookieCsrf())
                                 .with(new SetServerNameRequestPostProcessor(trustedButExpiredCertZone.getIdentityZone().getSubdomain()+".localhost"))
                                 .param("username", "marissa2")
                                 .param("password", LDAP))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?error=login_failure"))
            .andExpect(unauthenticated());
    }

}
