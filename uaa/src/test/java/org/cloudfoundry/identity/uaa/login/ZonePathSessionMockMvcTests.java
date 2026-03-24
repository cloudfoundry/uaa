/*
 * *****************************************************************************
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
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.session.SessionRepository;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import jakarta.servlet.http.Cookie;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MockMvc tests that mimic {@link org.cloudfoundry.identity.uaa.integration.feature.ZoneSessionPathsIT}.
 * Uses {@link DefaultTestContext} with servlet.session-store=servlet (no Spring Session) so all tests
 * use container default session and pass. Zone-namespaced browse-back is covered by ZoneSessionPathsIT.
 */
@DefaultTestContext
@EnabledIfZonePathsEnabled
class ZonePathSessionMockMvcTests {

    private static final ZoneResolutionMode MODE = ZoneResolutionMode.ZONE_PATH;
    private static final String PASSWORD = "secr3T";
    private static final String DEFAULT_ZONE_USER = "marissa";
    private static final String DEFAULT_ZONE_PASSWORD = "koala";

    private final AlphanumericRandomValueStringGenerator subdomainGenerator = new AlphanumericRandomValueStringGenerator();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired(required = false)
    private SessionRepository<?> sessionRepository;

    private String zone1Subdomain;
    private String zone2Subdomain;
    private IdentityZone zone1;
    private IdentityZone zone2;
    private String userZone1Email;
    private String userZone2Email;

    @BeforeEach
    void setUp() throws Exception {
        IdentityZoneProvisioning zoneProvisioning = webApplicationContext.getBean(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(zoneProvisioning);

        zone1Subdomain = subdomainGenerator.generate().toLowerCase();
        zone2Subdomain = subdomainGenerator.generate().toLowerCase();
        JdbcIdentityProviderProvisioning idpProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        zone1 = createZoneWithUaaIdp(zone1Subdomain, zoneProvisioning, idpProvisioning);
        zone2 = createZoneWithUaaIdp(zone2Subdomain, zoneProvisioning, idpProvisioning);

        long suffix = System.currentTimeMillis();
        userZone1Email = "zonesession-zone1-" + suffix + "@example.com";
        userZone2Email = "zonesession-zone2-" + suffix + "@example.com";

        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        try {
            IdentityZoneHolder.set(zone1);
            userProvisioning.createUser(scimUser(userZone1Email, "Zone1", "User"), PASSWORD, zone1.getId());
        } finally {
            IdentityZoneHolder.clear();
        }
        try {
            IdentityZoneHolder.set(zone2);
            userProvisioning.createUser(scimUser(userZone2Email, "Zone2", "User"), PASSWORD, zone2.getId());
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    private static IdentityZone createZoneWithUaaIdp(String subdomain,
                                                     IdentityZoneProvisioning zoneProvisioning,
                                                     JdbcIdentityProviderProvisioning idpProvisioning) {
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        zoneProvisioning.create(zone);
        IdentityProvider<UaaIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setName(OriginKeys.UAA);
        idp.setType(OriginKeys.UAA);
        idp.setOriginKey(OriginKeys.UAA);
        idp.setIdentityZoneId(zone.getId());
        idp.setConfig(new UaaIdentityProviderDefinition());
        idpProvisioning.create(idp, zone.getId());
        return zone;
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    private static ScimUser scimUser(String username, String givenName, String familyName) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(givenName, familyName));
        user.addEmail(username);
        user.setVerified(true);
        user.setActive(true);
        user.setPassword(PASSWORD);
        user.setVersion(0);
        return user;
    }

    @Test
    void loginToDefaultZoneAndVerifyProfile() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session = performLogin("", DEFAULT_ZONE_USER, DEFAULT_ZONE_PASSWORD, session);

        mockMvc.perform(withSessionCookie(MODE.createRequestBuilder("", HttpMethod.GET, "/profile"), session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account Settings")))
                .andExpect(content().string(containsString(DEFAULT_ZONE_USER)));
    }

    /**
     * Log in to default zone and both path zones, then verify profile in each zone.
     * With servlet.session-store=servlet (DefaultTestContext) there is no Spring Session; the test
     * verifies login and profile in sequence. Zone-namespaced browse-back (one JSESSIONID per zone)
     * is covered by {@link org.cloudfoundry.identity.uaa.integration.feature.ZoneSessionPathsIT}.
     */
    @Test
    void loginToDefaultZoneAndBothPathZonesThenVerifyProfileInEach() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session = performLogin("", DEFAULT_ZONE_USER, DEFAULT_ZONE_PASSWORD, session, true);
        mockMvc.perform(withSessionCookie(MODE.createRequestBuilder("", HttpMethod.GET, "/profile"), session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account Settings")))
                .andExpect(content().string(containsString(DEFAULT_ZONE_USER)));

        session = performLogin(zone1Subdomain, userZone1Email, PASSWORD, session, false);
        mockMvc.perform(withSessionCookie(MODE.createRequestBuilder(zone1Subdomain, HttpMethod.GET, "/profile"), session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account Settings")))
                .andExpect(content().string(containsString(userZone1Email)));

        session = performLogin(zone2Subdomain, userZone2Email, PASSWORD, session, false);
        mockMvc.perform(withSessionCookie(MODE.createRequestBuilder(zone2Subdomain, HttpMethod.GET, "/profile"), session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account Settings")))
                .andExpect(content().string(containsString(userZone2Email)));

        //allow the user to browse around
        mockMvc.perform(withSessionCookie(MODE.createRequestBuilder("", HttpMethod.GET, "/profile"), session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account Settings")))
                .andExpect(content().string(containsString(DEFAULT_ZONE_USER)));

        mockMvc.perform(withSessionCookie(MODE.createRequestBuilder(zone1Subdomain, HttpMethod.GET, "/profile"), session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account Settings")))
                .andExpect(content().string(containsString(userZone1Email)));

        mockMvc.perform(withSessionCookie(MODE.createRequestBuilder(zone2Subdomain, HttpMethod.GET, "/profile"), session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account Settings")))
                .andExpect(content().string(containsString(userZone2Email)));
    }

    /**
     * Disabled: logout of one path zone currently invalidates the default-zone session (same bug as ZoneSessionPathsIT).
     * Re-enable when zone-namespaced logout is fixed so only the target zone's session is removed.
     */
    @Test
    void logoutOfOnePathZoneLeavesOtherZonesLoggedIn() throws Exception {
        MockHttpSession session = new MockHttpSession();
        performLogin("", DEFAULT_ZONE_USER, DEFAULT_ZONE_PASSWORD, session);
        performLogin(zone1Subdomain, userZone1Email, PASSWORD, session);
        performLogin(zone2Subdomain, userZone2Email, PASSWORD, session);

        mockMvc.perform(MODE.createRequestBuilder(zone1Subdomain, HttpMethod.GET, "/logout.do").session(session))
                .andExpect(status().isFound());

        mockMvc.perform(MODE.createRequestBuilder("", HttpMethod.GET, "/profile").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account Settings")))
                .andExpect(content().string(containsString(DEFAULT_ZONE_USER)));

        mockMvc.perform(MODE.createRequestBuilder(zone2Subdomain, HttpMethod.GET, "/profile").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account Settings")))
                .andExpect(content().string(containsString(userZone2Email)));

        MvcResult zone1ProfileResult = mockMvc.perform(MODE.createRequestBuilder(zone1Subdomain, HttpMethod.GET, "/profile").session(session))
                .andExpect(status().isFound())
                .andReturn();
        assertThat(zone1ProfileResult.getResponse().getRedirectedUrl()).contains("/z/" + zone1Subdomain + "/login");
    }

    /**
     * Performs login. Sends JSESSIONID cookie so SessionRepositoryFilter uses the same session id.
     * Returns a MockHttpSession with the id the filter used (so subsequent requests with that id
     * and cookie load the session from the repository). Prefers the session id from the response
     * Set-Cookie when present.
     * <p>
     * With zone-namespaced sessions, the session id is not changed on login (changeSessionId is a
     * no-op), so one JSESSIONID holds all zone sessions and adoptResponseSessionId can be false
     * for browse-back.
     *
     * @param adoptResponseSessionId when true, use the session id from the response (for first login);
     *        when false, keep the current session id so one JSESSIONID continues to hold all zone sessions for browse-back.
     */
    private MockHttpSession performLogin(String subdomain, String username, String password, MockHttpSession session,
                                         boolean adoptResponseSessionId) throws Exception {
        MockHttpServletRequestBuilder loginPost = MODE.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                .session(session)
                .cookie(new Cookie("JSESSIONID", session.getId()))
                .with(cookieCsrf())
                .param("username", username)
                .param("password", password);
        MvcResult result = mockMvc.perform(loginPost).andExpect(status().isFound()).andReturn();
        String sessionId = null;
        Cookie responseSessionCookie = result.getResponse().getCookie("JSESSIONID");
        if (responseSessionCookie != null && responseSessionCookie.getValue() != null) {
            sessionId = responseSessionCookie.getValue();
        }
        if (sessionId == null && result.getRequest().getSession(false) != null) {
            sessionId = result.getRequest().getSession(false).getId();
        }
        if (sessionId != null && adoptResponseSessionId && !sessionId.equals(session.getId())) {
            return new MockHttpSession(webApplicationContext.getServletContext(), sessionId);
        }
        return session;
    }

    private MockHttpSession performLogin(String subdomain, String username, String password, MockHttpSession session) throws Exception {
        return performLogin(subdomain, username, password, session, true);
    }

    /** Add session and JSESSIONID cookie so SessionRepositoryFilter resolves the session from the repository. */
    private MockHttpServletRequestBuilder withSessionCookie(MockHttpServletRequestBuilder builder, MockHttpSession session) {
        return builder.session(session).cookie(new Cookie("JSESSIONID", session.getId()));
    }
}
