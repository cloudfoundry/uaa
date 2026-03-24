package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtilsZonePath;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import java.util.Date;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Same scenarios as {@link ForcePasswordChangeControllerMockMvcTest} but run with
 * {@link ZoneResolutionMode#SUBDOMAIN} and {@link ZoneResolutionMode#ZONE_PATH} so that
 * force password change is covered for subdomain-based and path-based identity zones.
 */
@DefaultTestContext
@EnabledIfZonePathsEnabled
class ForcePasswordChangeControllerZonePathMockMvcTest {

    private ScimUser user;
    private String token;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private IdentityZoneConfiguration uaaZoneConfig;
    private IdentityZoneCreationResult zoneResult;
    private String subdomain;

    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;

    /** Creates a zone (with admin client) and a user in that zone; sets {@link #subdomain}, {@link #zoneResult}, {@link #user}, {@link #token}. */
    void setupZoneAndUser(ZoneResolutionMode mode) throws Exception {
        subdomain = new AlphanumericRandomValueStringGenerator().generate().toLowerCase();
        UaaClientDetails adminClient = new UaaClientDetails("admin", null, null, "client_credentials",
                "clients.admin,scim.read,scim.write,idps.write,uaa.admin", "http://redirect.url");
        adminClient.setClientSecret("admin-secret");
        zoneResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, adminClient, IdentityZoneHolder.getCurrentZoneId());
        token = MockMvcUtilsZonePath.getClientCredentialsOAuthAccessToken(mode, mockMvc, "admin", "admin-secret", null, subdomain, false);
        String username = new AlphanumericRandomValueStringGenerator().generate() + "@test.org";
        ScimUser newUser = new ScimUser(null, username, "givenname", "familyname");
        newUser.setPrimaryEmail(username);
        newUser.setPassword("secret");
        user = MockMvcUtilsZonePath.createUserInZone(mode, mockMvc, token, newUser, zoneResult.getIdentityZone().getSubdomain(), null);
    }

    @BeforeEach
    void setup() throws Exception {
        identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(webApplicationContext, "uaa");
    }

    @AfterEach
    void cleanup() {
        MockMvcUtils.setZoneConfiguration(webApplicationContext, "uaa", uaaZoneConfig);
        IdentityZoneHolder.set(IdentityZone.getUaa());
    }

    private static String expectedRedirectBase(ZoneResolutionMode mode, String subdomain) {
        return mode == ZoneResolutionMode.ZONE_PATH
                ? "http://localhost/z/" + subdomain
                : "http://" + subdomain + ".localhost";
    }

    @Nested
    @DefaultTestContext
    class HappyPath {

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void requires_user_to_change_password(ZoneResolutionMode mode) throws Exception {
            setupZoneAndUser(mode);
            UserAccountStatus userAccountStatus = new UserAccountStatus();
            userAccountStatus.setPasswordChangeRequired(true);
            String jsonStatus = JsonUtils.writeValueAsString(userAccountStatus);
            mockMvc.perform(
                            mode.createRequestBuilder(subdomain, HttpMethod.PATCH, "/Users/" + user.getId() + "/status")
                                    .header("Authorization", "Bearer " + token)
                                    .accept(APPLICATION_JSON)
                                    .contentType(APPLICATION_JSON)
                                    .content(jsonStatus))
                    .andExpect(status().isOk());

            MockHttpSession session = new MockHttpSession();
            MockHttpServletRequestBuilder loginPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                    .param("username", user.getUserName())
                    .param("password", "secret")
                    .session(session)
                    .with(cookieCsrf())
                    .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");
            mockMvc.perform(loginPost)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/" : "/"));

            assertThat(((SecurityContext) MockMvcUtils.getZoneSession(session, mode, subdomain).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated()).isTrue();
            assertThat(SessionUtils.isPasswordChangeRequired(MockMvcUtils.getZoneSession(session, mode, subdomain))).isTrue();

            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/").session(session))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/force_password_change" : "/force_password_change"));

            assertThat(SessionUtils.isPasswordChangeRequired(MockMvcUtils.getZoneSession(session, mode, subdomain))).isTrue();

            MockHttpServletRequestBuilder validPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/force_password_change")
                    .param("password", "test")
                    .param("password_confirmation", "test")
                    .session(session)
                    .with(cookieCsrf());
            mockMvc.perform(validPost)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/force_password_change_completed" : "/force_password_change_completed"));
            assertThat(SessionUtils.isPasswordChangeRequired(MockMvcUtils.getZoneSession(session, mode, subdomain))).isFalse();

            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/force_password_change_completed").session(session))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(expectedRedirectBase(mode, subdomain) + "/"));
            assertThat(SessionUtils.isPasswordChangeRequired(MockMvcUtils.getZoneSession(session, mode, subdomain))).isFalse();
        }

        /**
         * force_password_change page must render form action zone-aware.
         * Passes for SUBDOMAIN; will pass for ZONE_PATH once template/controller are zone path aware.
         */
        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void force_password_change_page_contains_zone_aware_form_action(ZoneResolutionMode mode) throws Exception {
            setupZoneAndUser(mode);
            UserAccountStatus userAccountStatus = new UserAccountStatus();
            userAccountStatus.setPasswordChangeRequired(true);
            String jsonStatus = JsonUtils.writeValueAsString(userAccountStatus);
            mockMvc.perform(
                            mode.createRequestBuilder(subdomain, HttpMethod.PATCH, "/Users/" + user.getId() + "/status")
                                    .header("Authorization", "Bearer " + token)
                                    .accept(APPLICATION_JSON)
                                    .contentType(APPLICATION_JSON)
                                    .content(jsonStatus))
                    .andExpect(status().isOk());

            MockHttpSession session = new MockHttpSession();
            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                            .param("username", user.getUserName())
                            .param("password", "secret")
                            .session(session)
                            .with(cookieCsrf())
                            .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1"))
                    .andExpect(status().isFound());

            String expectedFormAction = mode == ZoneResolutionMode.ZONE_PATH
                    ? "action=\"/z/" + subdomain + "/force_password_change\"" : "action=\"/force_password_change\"";

            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/force_password_change").session(session))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString(expectedFormAction)));
        }
    }

    @Nested
    @DefaultTestContext
    class WithPasswordPolicy {

        @ParameterizedTest
        @MethodSource("org.cloudfoundry.identity.uaa.login.ForcePasswordChangeControllerZonePathMockMvcTest#authenticationTestParamsWithZoneModes")
        void force_password_change_with_invalid_password(
                ForcePasswordChangeControllerMockMvcTest.PasswordPolicyWithInvalidPassword passwordPolicyWithInvalidPassword,
                ZoneResolutionMode mode) throws Exception {
            setupZoneAndUser(mode);
            IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, zoneResult.getIdentityZone().getId());
            UaaIdentityProviderDefinition cleanIdpDefinition = (UaaIdentityProviderDefinition) identityProvider.getConfig();
            try {
                identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicyWithInvalidPassword.passwordPolicy, null));
                identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

            UserAccountStatus userAccountStatus = new UserAccountStatus();
            userAccountStatus.setPasswordChangeRequired(true);
            String jsonStatus = JsonUtils.writeValueAsString(userAccountStatus);
            mockMvc.perform(
                            mode.createRequestBuilder(subdomain, HttpMethod.PATCH, "/Users/" + user.getId() + "/status")
                                    .header("Authorization", "Bearer " + token)
                                    .accept(APPLICATION_JSON)
                                    .contentType(APPLICATION_JSON)
                                    .content(jsonStatus))
                    .andExpect(status().isOk());

            MockHttpSession session = new MockHttpSession();
            Cookie cookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");

            MockHttpServletRequestBuilder invalidPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                    .param("username", user.getUserName())
                    .param("password", "secret")
                    .session(session)
                    .cookie(cookie)
                    .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");
            mockMvc.perform(invalidPost)
                    .andExpect(status().isFound());

            MockHttpServletRequestBuilder validPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/force_password_change")
                    .param("password", passwordPolicyWithInvalidPassword.password)
                    .param("password_confirmation", passwordPolicyWithInvalidPassword.password)
                    .session(session)
                    .cookie(cookie)
                    .with(cookieCsrf());
            mockMvc.perform(validPost)
                    .andExpect(view().name("force_password_change"))
                    .andExpect(model().attribute("message", passwordPolicyWithInvalidPassword.errorMessage))
                    .andExpect(model().attribute("email", user.getPrimaryEmail()));
            } finally {
                identityProvider.setConfig(cleanIdpDefinition);
                identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
            }
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void force_password_when_system_was_configured(ZoneResolutionMode mode) throws Exception {
            setupZoneAndUser(mode);
            IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, zoneResult.getIdentityZone().getId());
            UaaIdentityProviderDefinition cleanIdpDefinition = (UaaIdentityProviderDefinition) identityProvider.getConfig();
            try {
            PasswordPolicy passwordPolicy = new PasswordPolicy(4, 20, 0, 0, 0, 0, 0);
            passwordPolicy.setPasswordNewerThan(new Date(System.currentTimeMillis()));
            identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

            MockHttpSession session = new MockHttpSession();
            MockHttpServletRequestBuilder loginPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                    .param("username", user.getUserName())
                    .param("password", "secret")
                    .session(session)
                    .with(cookieCsrf())
                    .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");
            mockMvc.perform(loginPost)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/" : "/"));

            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/").session(session))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/force_password_change" : "/force_password_change"));

            MockHttpServletRequestBuilder validPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/force_password_change")
                    .param("password", "test")
                    .param("password_confirmation", "test")
                    .session(session)
                    .with(cookieCsrf());
            mockMvc.perform(validPost)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/force_password_change_completed" : "/force_password_change_completed"));

            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/force_password_change_completed").session(session))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(expectedRedirectBase(mode, subdomain) + "/"));
            assertThat(SessionUtils.isPasswordChangeRequired(MockMvcUtils.getZoneSession(session, mode, subdomain))).isFalse();
            } finally {
                identityProvider.setConfig(cleanIdpDefinition);
                identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
            }
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void submit_password_change_when_not_authenticated(ZoneResolutionMode mode) throws Exception {
        setupZoneAndUser(mode);
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.setPasswordChangeRequired(true);
        String jsonStatus = JsonUtils.writeValueAsString(userAccountStatus);
        mockMvc.perform(
                        mode.createRequestBuilder(subdomain, HttpMethod.PATCH, "/Users/" + user.getId() + "/status")
                                .header("Authorization", "Bearer " + token)
                                .accept(APPLICATION_JSON)
                                .contentType(APPLICATION_JSON)
                                .content(jsonStatus))
                .andExpect(status().isOk());

        MockHttpServletRequestBuilder validPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test");
        validPost.with(cookieCsrf());
        String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH
                ? "http://localhost/z/" + subdomain + "/login"
                : "http://" + subdomain + ".localhost/login";
        mockMvc.perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirect));
    }

    static Stream<Arguments> authenticationTestParamsWithZoneModes() {
        return ForcePasswordChangeControllerMockMvcTest.authenticationTestParams()
                .flatMap(pp -> Stream.of(ZoneResolutionMode.values()).map(mode -> Arguments.of(pp, mode)));
    }
}
