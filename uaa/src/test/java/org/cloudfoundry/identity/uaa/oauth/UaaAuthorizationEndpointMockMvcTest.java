package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.ZoneSeeder;
import org.cloudfoundry.identity.uaa.test.ZoneSeederExtension;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;

import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.REDIRECT_URI;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.SCOPE;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(ZoneSeederExtension.class)
@DefaultTestContext
class UaaAuthorizationEndpointMockMvcTest {

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
    class WhenRedirectUriAllowUnsafeMatchingIsEnabled {

        @Nested
        @DefaultTestContext
        class WhenConfiguredRedirectUriHasWildcards {
            @BeforeEach
            void setUp() {
                zoneSeeder.withClientWithImplicitAndAuthorizationCodeGrants(REDIRECT_CLIENT_ID, "http://sample.com/a/*");
            }

            @Test
            void shouldRedirect_whenItReliesOnLegacyWildcardBehavior() throws Exception {
                mockMvc.perform(implicitGrantAuthorizeRequest("http://sample.com/a/b"))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", startsWith("http://sample.com/a/b#token_type=bearer&access_token=")));

                mockMvc.perform(authCodeAuthorizeRequest("http://sample.com/a/b"))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", startsWith("http://sample.com/a/b?code=")));
            }

            @Test
            void shouldRedirect_whenTheRequestRedirectUriIsAnExactMatch() throws Exception {
                mockMvc.perform(implicitGrantAuthorizeRequest("http://sample.com/a/b"))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", startsWith("http://sample.com/a/b#token_type=bearer&access_token=")));

                mockMvc.perform(authCodeAuthorizeRequest("http://sample.com/a/b"))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", startsWith("http://sample.com/a/b?code=")));
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
                mockMvc.perform(implicitGrantAuthorizeRequest("http://subdomain.sample.com/path"))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", startsWith("http://subdomain.sample.com/path#token_type=bearer&access_token=")));

                mockMvc.perform(authCodeAuthorizeRequest("http://subdomain.sample.com/path"))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", startsWith("http://subdomain.sample.com/path?code=")));
            }

            @Test
            void shouldRedirect_whenTheRequestRedirectUriIsAnExactMatch() throws Exception {
                mockMvc.perform(implicitGrantAuthorizeRequest("http://sample.com"))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", startsWith("http://sample.com#token_type=bearer&access_token=")));

                mockMvc.perform(authCodeAuthorizeRequest("http://sample.com"))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", startsWith("http://sample.com?code=")));
            }
        }
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(
            properties = "uaa.oauth.redirect_uri.allow_unsafe_matching=false"
    )
    class WhenRedirectUriAllowUnsafeMatchingIsDisabled {  // "spec-compliant" mode

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
            void shouldFail_whenTheRequestReliesOnLegacyWildcardMatchingBehavior() throws Exception {
                mockMvc.perform(implicitGrantAuthorizeRequest("http://sample.com/a/b"))
                        .andExpect(status().isBadRequest())
                        .andExpect(forwardedUrl("/oauth/error"))
                        .andExpect(model().attribute("error", instanceOf(RedirectMismatchException.class)))
                        .andExpect(model().attribute("error", hasProperty("message",
                                is("Invalid redirect http://sample.com/a/b did not match one of the registered values")
                        )));

                mockMvc.perform(authCodeAuthorizeRequest("http://sample.com/a/b"))
                        .andExpect(status().isBadRequest())
                        .andExpect(forwardedUrl("/oauth/error"))
                        .andExpect(model().attribute("error", instanceOf(RedirectMismatchException.class)))
                        .andExpect(model().attribute("error", hasProperty("message",
                                is("Invalid redirect http://sample.com/a/b did not match one of the registered values")
                        )));
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
                mockMvc.perform(implicitGrantAuthorizeRequest("http://subdomain.sample.com"))
                        .andExpect(status().isBadRequest())
                        .andExpect(forwardedUrl("/oauth/error"))
                        .andExpect(model().attribute("error", instanceOf(RedirectMismatchException.class)))
                        .andExpect(model().attribute("error", hasProperty("message",
                                is("Invalid redirect http://subdomain.sample.com did not match one of the registered values")
                        )));

                mockMvc.perform(authCodeAuthorizeRequest("http://subdomain.sample.com/path"))
                        .andExpect(status().isBadRequest())
                        .andExpect(forwardedUrl("/oauth/error"))
                        .andExpect(model().attribute("error", instanceOf(RedirectMismatchException.class)))
                        .andExpect(model().attribute("error", hasProperty("message",
                                is("Invalid redirect http://subdomain.sample.com/path did not match one of the registered values")
                        )));
            }

            @Test
            void shouldRedirect_whenTheRequestRedirectUriIsAnExactMatch() throws Exception {
                mockMvc.perform(implicitGrantAuthorizeRequest("http://sample.com"))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", startsWith("http://sample.com#token_type=bearer&access_token=")));

                mockMvc.perform(authCodeAuthorizeRequest("http://sample.com"))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", startsWith("http://sample.com?code=")));
            }
        }
    }

    private void loginUser(ZoneSeeder zoneSeeder, String userEmail) {
        ScimUser user = zoneSeeder.getUserByEmail(userEmail);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), user.getOrigin(), user.getExternalId(), zoneSeeder.getIdentityZoneId());
        UaaAuthentication principal = new UaaAuthentication(uaaPrincipal, Collections.singletonList(UaaAuthority.fromAuthorities("uaa.user")), null);
        session = new MockHttpSession();
        session.setAttribute(
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
}
