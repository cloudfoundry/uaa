package org.cloudfoundry.identity.uaa.mock.ldap;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.InMemoryLdapServer;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpMethod;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.FileSystemUtils;
import org.springframework.web.context.WebApplicationContext;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.io.File;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
@ExtendWith(InMemoryLdapServer.LdapTrustStoreExtension.class)
@EnabledIfZonePathsEnabled
class LdapCertificateMockMvcZonePathTests {
    private static File ldapRootDirectoryExpired;
    private static File ldapRootDirectoryValid;
    private static InMemoryLdapServer validLdapCertServer;
    private static InMemoryLdapServer expiredLdapCertServer;
    private MockMvcUtils.IdentityZoneCreationResult trustedCertZone;
    private MockMvcUtils.IdentityZoneCreationResult trustedButExpiredCertZone;

    private RandomValueStringGenerator gen = new RandomValueStringGenerator(8);

    private MockMvc mockMvc;

    @BeforeAll
    static void startLdapsServers() {
        ClassLoader classLoader = LdapCertificateMockMvcZonePathTests.class.getClassLoader();

        File expiredKeystore = new File(classLoader.getResource("certs/expired-self-signed-ldap-cert.jks").getFile());
        File validKeystore = new File(classLoader.getResource("certs/valid-self-signed-ldap-cert.jks").getFile());
        RandomValueStringGenerator generator = new RandomValueStringGenerator();
        ldapRootDirectoryValid = new File(System.getProperty("java.io.tmpdir"), generator.generate());
        ldapRootDirectoryExpired = new File(System.getProperty("java.io.tmpdir"), generator.generate());

        validLdapCertServer = InMemoryLdapServer.startLdapWithTls(validKeystore);
        expiredLdapCertServer = InMemoryLdapServer.startLdapWithTls(expiredKeystore);
    }

    @AfterAll
    static void stopLdapsServers() {
        validLdapCertServer.stop();
        expiredLdapCertServer.stop();
        FileSystemUtils.deleteRecursively(ldapRootDirectoryValid);
        FileSystemUtils.deleteRecursively(ldapRootDirectoryExpired);
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
                validLdapCertServer.getUrl(),
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
        definition.setBaseUrl(expiredLdapCertServer.getUrl());
        MockMvcUtils.createIdentityProvider(mockMvc, trustedButExpiredCertZone, OriginKeys.LDAP, definition);
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void trusted_server_certificate(ZoneResolutionMode mode) throws Exception {
        String subdomain = trustedCertZone.getIdentityZone().getSubdomain();
        String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/" : "/";
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                .accept(TEXT_HTML_VALUE)
                .with(cookieCsrf())
                .param("username", "marissa2")
                .param("password", LDAP))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirect))
                .andExpect(authenticated());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void trusted_but_expired_server_certificate(ZoneResolutionMode mode) throws Exception {
        String expectedRedirectUrl = mode == ZoneResolutionMode.SUBDOMAIN ?
                "/login?error=login_failure" :
                "/z/" + trustedButExpiredCertZone.getIdentityZone().getSubdomain() + "/login?error=login_failure";
        mockMvc.perform(mode.createRequestBuilder(trustedButExpiredCertZone.getIdentityZone().getSubdomain(), HttpMethod.POST, "/login.do")
                .accept(TEXT_HTML_VALUE)
                .with(cookieCsrf())
                .param("username", "marissa2")
                .param("password", LDAP))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl))
                .andExpect(unauthenticated());
    }
}
