package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.ZoneSeeder;
import org.cloudfoundry.identity.uaa.test.ZoneSeederExtension;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpSession;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.REDIRECT_URI;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.SCOPE;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(ZoneSeederExtension.class)
@DefaultTestContext
@EnabledIfZonePathsEnabled
class UaaAuthorizationEndpointMockMvcZonePathTest {

    private static final String REDIRECT_CLIENT_ID = "redirect-client";

    @Autowired
    protected WebApplicationContext webApplicationContext;

    @Autowired
    protected MockMvc mockMvc;

    private MockHttpSession session;
    private ZoneSeeder zoneSeeder;

    @BeforeEach
    void setUp(ZoneSeeder zoneSeeder) {
        final String userEmail = "userEmail@example.com";
        this.zoneSeeder = zoneSeeder.withDefaults()
                .withUser(userEmail)
                .afterSeeding(zs -> loginUser(zs, userEmail));
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(
            properties = "uaa.oauth.redirect_uri.allow_unsafe_matching=true"
    )
    class WhenRedirectUriAllowUnsafeMatchingIsEnabled {

        @Autowired // Need a new mockMvc which is tied to the new web app context created by @TestPropertySource
        protected MockMvc mockMvc;

        @Nested
        @DefaultTestContext
        class WhenConfiguredRedirectUriHasWildcards {
            @BeforeEach
            void setUp() {
                zoneSeeder.withClientWithImplicitAndAuthorizationCodeGrants(REDIRECT_CLIENT_ID, "http://sample.com/a/*");
            }

            @Test
            void shouldRedirect_whenItReliesOnLegacyWildcardBehavior() throws Exception {
                MvcResult implicitResult = mockMvc.perform(implicitGrantAuthorizeRequest("http://sample.com/a/b"))
                        .andExpect(status().isFound())
                        .andReturn();
                assertThat(implicitResult.getResponse().getHeader("Location")).startsWith("http://sample.com/a/b#token_type=bearer&access_token=");

                MvcResult authCodeResult = mockMvc.perform(authCodeAuthorizeRequest("http://sample.com/a/b"))
                        .andExpect(status().isFound())
                        .andReturn();
                assertThat(authCodeResult.getResponse().getHeader("Location")).startsWith("http://sample.com/a/b?code=");
            }
        }

        @Nested
        @DefaultTestContext
        class WhenConfiguredRedirectUriDoesNotHaveWildcards {
            @BeforeEach
            void setUp() {
                zoneSeeder.withClientWithImplicitAndAuthorizationCodeGrants(REDIRECT_CLIENT_ID, "http://sample.com");
            }

            @Test
            void shouldRedirect_whenItReliesOnLegacyImplicitMatchingBehavior() throws Exception {
                MvcResult implicitResult = mockMvc.perform(implicitGrantAuthorizeRequest("http://subdomain.sample.com/path"))
                        .andExpect(status().isFound())
                        .andReturn();
                assertThat(implicitResult.getResponse().getHeader("Location")).startsWith("http://subdomain.sample.com/path#token_type=bearer&access_token=");

                MvcResult authCodeResult = mockMvc.perform(authCodeAuthorizeRequest("http://subdomain.sample.com/path"))
                        .andExpect(status().isFound())
                        .andReturn();
                assertThat(authCodeResult.getResponse().getHeader("Location")).startsWith("http://subdomain.sample.com/path?code=");
            }

            @Test
            void shouldRedirect_whenTheRequestRedirectUriIsAnExactMatch() throws Exception {
                MvcResult implicitResult = mockMvc.perform(implicitGrantAuthorizeRequest("http://sample.com"))
                        .andExpect(status().isFound())
                        .andReturn();
                assertThat(implicitResult.getResponse().getHeader("Location")).startsWith("http://sample.com#token_type=bearer&access_token=");

                MvcResult authCodeResult = mockMvc.perform(authCodeAuthorizeRequest("http://sample.com"))
                        .andExpect(status().isFound())
                        .andReturn();
                assertThat(authCodeResult.getResponse().getHeader("Location")).startsWith("http://sample.com?code=");
            }
        }
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(
            properties = "uaa.oauth.redirect_uri.allow_unsafe_matching=false"
    )
    class WhenRedirectUriAllowUnsafeMatchingIsDisabled {  // "spec-compliant" mode

        @Autowired // New mockMvc tied to the new web app context created by @TestPropertySource
        protected MockMvc mockMvc;

        @Nested
        @DefaultTestContext
        class WhenConfiguredRedirectUriHasWildcards {
            @BeforeEach
            void setUp() {
                zoneSeeder.withClientWithImplicitAndAuthorizationCodeGrants(REDIRECT_CLIENT_ID, "http://sample.com/a/*");
            }

            @Test
            void shouldFail_whenTheRequestReliesOnLegacyWildcardMatchingBehavior() throws Exception {
                MvcResult implicitResult = mockMvc.perform(implicitGrantAuthorizeRequest("http://sample.com/a/b"))
                        .andExpect(status().isBadRequest())
                        .andExpect(forwardedUrl("/oauth/error"))
                        .andReturn();
                Object implicitError = implicitResult.getModelAndView().getModel().get("error");
                assertThat(implicitError).isInstanceOf(RedirectMismatchException.class);
                assertThat(((RedirectMismatchException) implicitError).getMessage())
                        .isEqualTo("Invalid redirect http://sample.com/a/b did not match one of the registered values");

                MvcResult authCodeResult = mockMvc.perform(authCodeAuthorizeRequest("http://sample.com/a/b"))
                        .andExpect(status().isBadRequest())
                        .andExpect(forwardedUrl("/oauth/error"))
                        .andReturn();
                Object authCodeError = authCodeResult.getModelAndView().getModel().get("error");
                assertThat(authCodeError).isInstanceOf(RedirectMismatchException.class);
                assertThat(((RedirectMismatchException) authCodeError).getMessage())
                        .isEqualTo("Invalid redirect http://sample.com/a/b did not match one of the registered values");
            }
        }

        @Nested
        @DefaultTestContext
        class WhenConfiguredRedirectUriDoesNotHaveWildcards {
            @BeforeEach
            void setUp() {
                zoneSeeder.withClientWithImplicitAndAuthorizationCodeGrants(REDIRECT_CLIENT_ID, "http://sample.com");
            }

            @Test
            void shouldFail_whenTheRequestReliesOnLegacyImplicitMatchingBehavior() throws Exception {
                MvcResult implicitResult = mockMvc.perform(implicitGrantAuthorizeRequest("http://subdomain.sample.com"))
                        .andExpect(status().isBadRequest())
                        .andExpect(forwardedUrl("/oauth/error"))
                        .andReturn();
                Object implicitError = implicitResult.getModelAndView().getModel().get("error");
                assertThat(implicitError).isInstanceOf(RedirectMismatchException.class);
                assertThat(((RedirectMismatchException) implicitError).getMessage())
                        .isEqualTo("Invalid redirect http://subdomain.sample.com did not match one of the registered values");

                MvcResult authCodeResult = mockMvc.perform(authCodeAuthorizeRequest("http://subdomain.sample.com/path"))
                        .andExpect(status().isBadRequest())
                        .andExpect(forwardedUrl("/oauth/error"))
                        .andReturn();
                Object authCodeError = authCodeResult.getModelAndView().getModel().get("error");
                assertThat(authCodeError).isInstanceOf(RedirectMismatchException.class);
                assertThat(((RedirectMismatchException) authCodeError).getMessage())
                        .isEqualTo("Invalid redirect http://subdomain.sample.com/path did not match one of the registered values");
            }

            @Test
            void shouldRedirect_whenTheRequestRedirectUriIsAnExactMatch() throws Exception {
                MvcResult implicitResult = mockMvc.perform(implicitGrantAuthorizeRequest("http://sample.com"))
                        .andExpect(status().isFound())
                        .andReturn();
                assertThat(implicitResult.getResponse().getHeader("Location")).startsWith("http://sample.com#token_type=bearer&access_token=");

                MvcResult authCodeResult = mockMvc.perform(authCodeAuthorizeRequest("http://sample.com"))
                        .andExpect(status().isFound())
                        .andReturn();
                assertThat(authCodeResult.getResponse().getHeader("Location")).startsWith("http://sample.com?code=");
            }
        }
    }

    private void loginUser(ZoneSeeder zoneSeeder, String userEmail) {
        ScimUser user = zoneSeeder.getUserByEmail(userEmail);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), user.getOrigin(), user.getExternalId(), zoneSeeder.getIdentityZoneId());
        UaaAuthentication principal = new UaaAuthentication(uaaPrincipal, Collections.singletonList(UaaAuthority.fromAuthorities("uaa.user")), null);
        session = new MockHttpSession();
        MockMvcUtils.getZoneSession(session).setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockMvcUtils.MockSecurityContext(principal)
        );
    }

    private MockHttpServletRequestBuilder implicitGrantAuthorizeRequest(String redirectUri) {
        return get("/oauth/authorize")
                .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                .param(RESPONSE_TYPE, "token")
                .param(CLIENT_ID, REDIRECT_CLIENT_ID)
                .param(SCOPE, "openid")
                .param(REDIRECT_URI, redirectUri)
                .session(session);
    }

    private MockHttpServletRequestBuilder authCodeAuthorizeRequest(String redirectUri) {
        return get("/oauth/authorize")
                .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                .param(RESPONSE_TYPE, "code")
                .param(CLIENT_ID, REDIRECT_CLIENT_ID)
                .param(SCOPE, "openid")
                .param(REDIRECT_URI, redirectUri)
                .session(session);
    }

    @Nested
    @DefaultTestContext
    class ConfirmAccessAndErrorZonePathSupport {

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void confirm_access_responds_for_zone_path(ZoneResolutionMode mode) throws Exception {
            String subdomain = "zone" + System.nanoTime();
            UaaClientDetails client = new UaaClientDetails("client-id", "", "openid", "authorization_code", "", "http://redirect");
            client.setClientSecret("secret");
            MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, client, IdentityZoneHolder.getCurrentZoneId());

            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/oauth/confirm_access"))
                    .andExpect(status().is3xxRedirection());
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void oauth_error_responds_for_zone_path(ZoneResolutionMode mode) throws Exception {
            String subdomain = "zone" + System.nanoTime();
            UaaClientDetails client = new UaaClientDetails("client-id", "", "openid", "authorization_code", "", "http://redirect");
            client.setClientSecret("secret");
            MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, client, IdentityZoneHolder.getCurrentZoneId());

            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/oauth/error"))
                    .andExpect(status().is3xxRedirection());
        }
    }
}
