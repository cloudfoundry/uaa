package org.cloudfoundry.identity.uaa.mock.ldap;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.ldap.server.ApacheDsSSLContainer;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.FileSystemUtils;
import org.springframework.web.context.WebApplicationContext;

import java.io.File;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class LdapCertificateMockMvcTests {
    private static final int LDAP_VALID_LDAP_PORT = 33390;
    private static final int LDAP_EXPIRED_LDAP_PORT = LDAP_VALID_LDAP_PORT + 1;
    private static final int LDAP_VALID_LDAPS_PORT = 33637;
    private static final int LDAP_EXPIRED_LDAPS_PORT = LDAP_VALID_LDAPS_PORT + 1;
    private static final String JAVAX_NET_SSL_TRUST_STORE = "javax.net.ssl.trustStore";
    private static File LDAP_ROOT_DIRECTORY_EXPIRED;

    private static File LDAP_ROOT_DIRECTORY_VALID;
    private static ApacheDsSSLContainer validLdapCertServer;
    private static ApacheDsSSLContainer expiredLdapCertServer;
    private MockMvcUtils.IdentityZoneCreationResult trustedCertZone;
    private MockMvcUtils.IdentityZoneCreationResult trustedButExpiredCertZone;

    private static String defaultTrustStore;

    private RandomValueStringGenerator gen = new RandomValueStringGenerator(8);

    private MockMvc mockMvc;

    @BeforeAll
    static void trustOurCustomCA() {
        ClassLoader classLoader = LdapCertificateMockMvcTests.class.getClassLoader();
        File file = new File(classLoader.getResource("certs/truststore-containing-the-ldap-ca.jks").getFile());

        defaultTrustStore = System.getProperty(JAVAX_NET_SSL_TRUST_STORE);
        System.setProperty(JAVAX_NET_SSL_TRUST_STORE, file.getAbsolutePath());
    }

    @BeforeAll
    static void startLdapsServers() throws Exception {
        ClassLoader classLoader = LdapCertificateMockMvcTests.class.getClassLoader();

        File expiredKeystore = new File(classLoader.getResource("certs/expired-self-signed-ldap-cert.jks").getFile());
        File validKeystore = new File(classLoader.getResource("certs/valid-self-signed-ldap-cert.jks").getFile());
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

    @AfterAll
    static void revertOurCustomCA() {
        if (defaultTrustStore != null) {
            System.setProperty(JAVAX_NET_SSL_TRUST_STORE, defaultTrustStore);
        } else {
            System.clearProperty(JAVAX_NET_SSL_TRUST_STORE);
        }
    }

    @AfterAll
    static void stopLdapsServers() {
        validLdapCertServer.stop();
        expiredLdapCertServer.stop();
        FileSystemUtils.deleteRecursively(LDAP_ROOT_DIRECTORY_VALID);
        FileSystemUtils.deleteRecursively(LDAP_ROOT_DIRECTORY_EXPIRED);
    }

    @BeforeEach
    void setUp(@Autowired WebApplicationContext webApplicationContext, @Autowired MockMvc mockMvc) throws Exception {
        this.mockMvc = mockMvc;

        trustedCertZone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                gen.generate(),
                mockMvc,
                webApplicationContext,
                null, IdentityZoneHolder.getCurrentZoneId());

        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                "ldaps://localhost:" + LDAP_VALID_LDAPS_PORT,
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

        MockMvcUtils.createIdentityProvider(mockMvc, trustedCertZone, OriginKeys.LDAP, definition);
        trustedButExpiredCertZone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                gen.generate(),
                mockMvc,
                webApplicationContext,
                null, IdentityZoneHolder.getCurrentZoneId());
        definition.setBaseUrl("ldaps://localhost:" + LDAP_EXPIRED_LDAPS_PORT);
        MockMvcUtils.createIdentityProvider(mockMvc, trustedButExpiredCertZone, OriginKeys.LDAP, definition);
    }

    @Test
    void trusted_server_certificate() throws Exception {
        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
                .with(cookieCsrf())
                .with(new SetServerNameRequestPostProcessor(trustedCertZone.getIdentityZone().getSubdomain() + ".localhost"))
                .param("username", "marissa2")
                .param("password", LDAP))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated());
    }

    @Test
    void trusted_but_expired_server_certificate() throws Exception {
        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
                .with(cookieCsrf())
                .with(new SetServerNameRequestPostProcessor(trustedButExpiredCertZone.getIdentityZone().getSubdomain() + ".localhost"))
                .param("username", "marissa2")
                .param("password", LDAP))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error=login_failure"))
                .andExpect(unauthenticated());
    }
}
