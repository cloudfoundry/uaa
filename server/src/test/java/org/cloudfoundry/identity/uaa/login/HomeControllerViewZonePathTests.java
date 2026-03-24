package org.cloudfoundry.identity.uaa.login;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.client.ClientMetadata;
import org.cloudfoundry.identity.uaa.client.JdbcClientMetadataProvisioning;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.home.HomeController;
import org.cloudfoundry.identity.uaa.provider.saml.MetadataProviderNotFoundException;
import org.cloudfoundry.identity.uaa.util.ZoneRequestPathMode;
import org.cloudfoundry.identity.uaa.util.beans.TestBuildInfo;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.ui.Model;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

/**
 * View tests for HomeController. Each test is parameterized by {@link ZoneRequestPathMode} so that
 * both default paths ({@code /home}, {@code /error}, ...) and zone paths ({@code /z/{subdomain}/home}, ...) are covered.
 */
@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@SpringJUnitConfig(classes = HomeControllerViewZonePathTests.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@EnabledIfZonePathsEnabled
class HomeControllerViewZonePathTests extends TestClassNullifier {

    // --- Zone path helpers (single place for all mode logic) ---

    /** Uses context path for ZONE_PATH so request matches ZonePathContextRewritingFilter output and Thymeleaf generates correct URLs. */
    private static MockHttpServletRequestBuilder request(ZoneRequestPathMode mode, String pathSuffix) {
        if (mode.redirectPrefix().isEmpty()) {
            return get(pathSuffix);
        }
        String ctx = "/z/" + mode.getSubdomain();
        // Servlet path must not end with '/' (MockHttpServletRequestBuilder constraint); use "" for root
        String servletPath = "/".equals(pathSuffix) ? "" : pathSuffix;
        return get(ctx + pathSuffix).contextPath(ctx).servletPath(servletPath);
    }

    /** Expected href string for nav/links: {@code href="/profile"} or {@code href="/z/test-zone/profile"}. */
    private static String expectedHref(ZoneRequestPathMode mode, String path) {
        String prefix = mode.redirectPrefix();
        return prefix.isEmpty() ? "href=\"" + path + "\"" : "href=\"" + prefix + path + "\"";
    }

    /** Expected resource path in response (e.g. script src, img src); Thymeleaf prefixes context path for ZONE_PATH. */
    private static String expectedResourcePath(ZoneRequestPathMode mode, String path) {
        return mode.redirectPrefix() + path;
    }

    /** Ensures current zone has test branding so error-page assertions (footer, logo) pass for ZONE_PATH. */
    private void applyTestBrandingToCurrentZone() {
        IdentityZoneConfiguration newConfiguration = new IdentityZoneConfiguration();
        newConfiguration.setBranding(new BrandingInformation());
        newConfiguration.getBranding().setFooterLegalText(customFooterText);
        newConfiguration.getBranding().setProductLogo(base64ProductLogo);
        IdentityZoneHolder.get().setConfig(newConfiguration);
    }

    // --- Constants and fields ---

    private static final String base64EncodedImg = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAXRQTFRFAAAAOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ozk4Ojo6Ojk5NkZMFp/PFqDPNkVKOjo6Ojk5MFhnEq3nEqvjEqzjEbDpMFdlOjo5Ojo6Ojo6Ozg2GZ3TFqXeFKfgF6DVOjo6Ozg2G5jPGZ7ZGKHbGZvROjo6Ojo5M1FfG5vYGp3aM1BdOjo6Ojo6Ojk4KHWeH5PSHpTSKHSbOjk4Ojo6Ojs8IY/QIY/QOjs7Ojo6Ojo6Ozc0JYfJJYjKOzYyOjo5Ozc0KX7AKH/AOzUxOjo5Ojo6Ojo6Ojo6Ojs8LHi6LHi6Ojs7Ojo6Ojo6Ojo6Ojo6Ojo6L3K5L3S7LnW8LnS7Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6NlFvMmWeMmaeNVJwOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojk5Ojk4Ojk4Ojk5Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6FaXeFabfGZ/aGKDaHJnVG5rW////xZzURgAAAHV0Uk5TAAACPaXbAVzltTa4MykoM5HlPY/k5Iw85QnBs2D7+lzAtWD7+lyO6EKem0Ey47Mx2dYvtVZVop5Q2i4qlZAnBiGemh0EDXuddqypcHkShPJwYufmX2rvihSJ+qxlg4JiqP2HPtnW1NjZ2svRVAglGTi91RAXr3/WIQAAAAFiS0dEe0/StfwAAAAJcEhZcwAAAEgAAABIAEbJaz4AAADVSURBVBjTY2BgYGBkYmZhZWVhZmJkAANGNnYODk5ODg52NrAIIyMXBzcPLx8/NwcXIyNYQEBQSFhEVExcQgAiICklLSNbWiYnLy0lCRFQUFRSLq9QUVVUgAgwqqlraFZWaWmrqzFCTNXR1dM3MDQy1tWB2MvIaMJqamZuYWnCCHeIlbWNrZ0VG5QPFLF3cHRydoErcHVz9/D08nb3kYSY6evnHxAYFBwSGhYeAbbWNzIqOiY2Lj4hMckVoiQ5JTUtPSMzKzsH6pfcvPyCwqKc4pJcoAAA2pghnaBVZ0kAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTUtMTAtMDhUMTI6NDg6MDkrMDA6MDDsQS6eAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE1LTEwLTA4VDEyOjQ4OjA5KzAwOjAwnRyWIgAAAEZ0RVh0c29mdHdhcmUASW1hZ2VNYWdpY2sgNi43LjgtOSAyMDE0LTA1LTEyIFExNiBodHRwOi8vd3d3LmltYWdlbWFnaWNrLm9yZ9yG7QAAAAAYdEVYdFRodW1iOjpEb2N1bWVudDo6UGFnZXMAMaf/uy8AAAAYdEVYdFRodW1iOjpJbWFnZTo6aGVpZ2h0ADE5Mg8AcoUAAAAXdEVYdFRodW1iOjpJbWFnZTo6V2lkdGgAMTky06whCAAAABl0RVh0VGh1bWI6Ok1pbWV0eXBlAGltYWdlL3BuZz+yVk4AAAAXdEVYdFRodW1iOjpNVGltZQAxNDQ0MzA4NDg5qdC9PQAAAA90RVh0VGh1bWI6OlNpemUAMEJClKI+7AAAAFZ0RVh0VGh1bWI6OlVSSQBmaWxlOi8vL21udGxvZy9mYXZpY29ucy8yMDE1LTEwLTA4LzJiMjljNmYwZWRhZWUzM2ViNmM1Mzg4ODMxMjg3OTg1Lmljby5wbmdoJKG+AAAAAElFTkSuQmCC";
    private static final String customFooterText = "custom footer text";
    private static final String base64ProductLogo = "D44vIpdmc0ne8IPLEbYD2vvLpu71spjxwaLYYdj39gTYa9kyWs";
    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    private IdentityZoneConfiguration originalConfiguration;

    @Autowired
    private HomeController homeController;

    @BeforeEach
    void beforeEach() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        originalConfiguration = IdentityZoneHolder.get().getConfig();
    }

    @AfterEach
    void afterEach() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        IdentityZoneHolder.get().setConfig(originalConfiguration);
    }

    // --- Tests (each parameterized by ZoneRequestPathMode) ---

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void tilesFromClientMetadataAndTilesConfigShown(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        applyTestBrandingToCurrentZone();
        mockMvc.perform(request(mode, "/"))
                .andDo(print())
                .andExpect(xpath("//*[@id='tile-1'][text()[contains(.,'client-1')]]").exists())
                .andExpect(xpath("//*[@class='tile-1']/@href").string("http://app.launch/url"))

                .andExpect(xpath("//head/style[2]").string(".tile-1 .tile-icon {background-image: url(\"data:image/png;base64," + base64EncodedImg + "\")}"))
                .andExpect(xpath("//*[@id='tile-2'][text()[contains(.,'Client 2 Name')]]").exists())
                .andExpect(xpath("//*[@class='tile-2']/@href").string("http://second.url/"))

                .andExpect(xpath("//*[@class='tile-3']").doesNotExist());
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void tilesFromClientMetadataAndTilesConfigShown_forOtherZone(ZoneRequestPathMode mode) throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone("test", "test");
        IdentityZoneHolder.set(identityZone);
        mockMvc.perform(request(mode, "/"))
                .andExpect(xpath("//*[@id='tile-1'][text()[contains(.,'client-1')]]").exists())
                .andExpect(xpath("//*[@class='tile-1']/@href").string("http://app.launch/url"))
                .andExpect(xpath("//head/style[1]").string(".tile-1 .tile-icon {background-image: url(\"data:image/png;base64," + base64EncodedImg + "\")}"))
                .andExpect(xpath("//*[@id='tile-2'][text()[contains(.,'Client 2 Name')]]").exists())
                .andExpect(xpath("//*[@class='tile-2']/@href").string("http://second.url/"))
                .andExpect(xpath("//*[@class='tile-3']").doesNotExist());
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void configuredHomePage(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        mockMvc.perform(request(mode, "/home"))
                .andExpect(status().isOk());

        String customHomePage = "http://custom.home/page";
        IdentityZoneHolder.get().getConfig().getLinks().setHomeRedirect(customHomePage);
        mockMvc.perform(request(mode, "/home"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", customHomePage));

        IdentityZone zone = MultitenancyFixture.identityZone("zone", "zone");
        zone.setConfig(new IdentityZoneConfiguration());
        IdentityZoneHolder.set(zone);
        mockMvc.perform(request(mode, "/home"))
                .andExpect(status().isOk());

        zone.getConfig().getLinks().setHomeRedirect(customHomePage);
        mockMvc.perform(request(mode, "/home"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", customHomePage));
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void homePageContainsCorrectNavLinks(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        mockMvc.perform(request(mode, "/home"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(expectedHref(mode, "/profile"))))
                .andExpect(content().string(containsString(expectedHref(mode, "/logout.do"))));
    }

    /**
     * Backwards compatibility: when UAA is deployed with context path /uaa (e.g. integration tests),
     * nav fragment must render profile and logout links with /uaa prefix so they point to the same app.
     */
    @ParameterizedTest
    @EnumSource(value = ZoneRequestPathMode.class, names = {"DEFAULT"})
    void homePageWithContextPath_containsNavLinksWithContextPath(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        mockMvc.perform(get("/uaa/home").contextPath("/uaa"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("href=\"/uaa/profile\"")))
                .andExpect(content().string(containsString("href=\"/uaa/logout.do\"")));
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void errorPageContainsCorrectNavLinks(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        mockMvc.perform(request(mode, "/error"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Uh oh.")));
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void errorPageContainsCorrectResourceLink(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        String imagePath = "/resources/images/sad_cloud.png";
        mockMvc.perform(request(mode, "/error"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("src=\"" + expectedResourcePath(mode, imagePath) + "\"")));
    }

    static Stream<Arguments> errorBrandingParams() {
        return Stream.of("/error", "/error404", "/error500", "/oauth_error", "/saml_error")
                .flatMap(url -> Stream.of(ZoneRequestPathMode.DEFAULT, ZoneRequestPathMode.ZONE_PATH)
                        .map(mode -> Arguments.of(mode, url)));
    }

    @ParameterizedTest
    @MethodSource("errorBrandingParams")
    void errorBranding(ZoneRequestPathMode mode, String errorUrl) throws Exception {
        mode.setZone();
        applyTestBrandingToCurrentZone();
        mockMvc.perform(request(mode, errorUrl).sessionAttr(WebAttributes.AUTHENTICATION_EXCEPTION, new InternalAuthenticationServiceException("auth error")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(customFooterText)))
                .andExpect(content().string(containsString(base64ProductLogo)));
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void errorOauthWithExceptionString(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        applyTestBrandingToCurrentZone();
        mockMvc.perform(request(mode, "/oauth_error").sessionAttr("oauth_error", "auth error"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(customFooterText)))
                .andExpect(content().string(containsString(base64ProductLogo)));
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void error500WithGenericException(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        applyTestBrandingToCurrentZone();
        mockMvc.perform(request(mode, "/error500").requestAttr(RequestDispatcher.ERROR_EXCEPTION, new Exception("bad")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(customFooterText)))
                .andExpect(content().string(containsString(base64ProductLogo)));
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void error500WithSAMLExceptionAsCause(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        applyTestBrandingToCurrentZone();
        mockMvc.perform(request(mode, "/error500").requestAttr(RequestDispatcher.ERROR_EXCEPTION, new Exception(new Saml2Exception("bad"))))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(customFooterText)))
                .andExpect(content().string(containsString(base64ProductLogo)));
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void error500WithMetadataProviderNotFoundExceptionCause(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        applyTestBrandingToCurrentZone();
        mockMvc.perform(request(mode, "/error500").requestAttr(RequestDispatcher.ERROR_EXCEPTION, new Exception(new MetadataProviderNotFoundException("bad", new RuntimeException()))))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(customFooterText)))
                .andExpect(content().string(containsString(base64ProductLogo)));
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void error429(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        mockMvc.perform(request(mode, "/error429"))
                .andExpect(status().isTooManyRequests());
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void errorRejection(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();
        mockMvc.perform(request(mode, "/rejected"))
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void handleRequestRejected(ZoneRequestPathMode mode) {
        assertThat(homeController.handleRequestRejected(
                mock(Model.class),
                new RequestRejectedException(""),
                "")).isEqualTo("external_auth_error");
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void configuredGlobalHomePage(ZoneRequestPathMode mode) throws Exception {
        mode.setZone();

        mockMvc.perform(request(mode, "/home"))
                .andExpect(status().isOk());

        String globalHomePage = "http://{zone.subdomain}.custom.home/{zone.id}";
        ReflectionTestUtils.setField(homeController, "globalLinks", new Links().setHomeRedirect(globalHomePage));

        String expectedGlobalRedirect = mode == ZoneRequestPathMode.ZONE_PATH
                ? "http://test-zone.custom.home/test-zone-id"
                : "http://.custom.home/uaa";
        mockMvc.perform(request(mode, "/home"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", expectedGlobalRedirect));

        String customHomePage = "http://custom.home/page";
        IdentityZoneHolder.get().getConfig().getLinks().setHomeRedirect(customHomePage);
        mockMvc.perform(request(mode, "/home"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", customHomePage));

        IdentityZone zone = MultitenancyFixture.identityZone("zoneId", "zonesubdomain");
        zone.setConfig(new IdentityZoneConfiguration());
        IdentityZoneHolder.set(zone);
        mockMvc.perform(request(mode, "/home"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "http://zonesubdomain.custom.home/zoneId"));

        zone.getConfig().getLinks().setHomeRedirect(customHomePage);
        mockMvc.perform(request(mode, "/home"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", customHomePage));
    }

    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration implements WebMvcConfigurer {

        @Autowired
        private RequestMappingHandlerAdapter requestMappingHandlerAdapter;

        @PostConstruct
        public void init() {
            requestMappingHandlerAdapter.setIgnoreDefaultModelOnRedirect(false);
        }

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Bean
        BuildInfo buildInfo() {
            return new TestBuildInfo();
        }

        @Bean
        JdbcClientMetadataProvisioning clientMetadataProvisioning() throws MalformedURLException {
            ClientMetadata clientMetadata1 = new ClientMetadata();
            clientMetadata1.setClientId("client-1");
            clientMetadata1.setShowOnHomePage(true);
            clientMetadata1.setAppLaunchUrl(URI.create("http://app.launch/url").toURL());
            clientMetadata1.setAppIcon(base64EncodedImg);

            ClientMetadata clientMetadata2 = new ClientMetadata();
            clientMetadata2.setClientId("client-2");
            clientMetadata2.setShowOnHomePage(true);
            clientMetadata2.setAppLaunchUrl(URI.create("http://second.url/").toURL());
            clientMetadata2.setAppIcon("base64-encoded-img");
            clientMetadata2.setClientName("Client 2 Name");

            ClientMetadata clientMetadataDoesNotExist = new ClientMetadata();
            clientMetadataDoesNotExist.setClientId("client-3");
            clientMetadataDoesNotExist.setShowOnHomePage(false);

            ClientMetadata clientMetadataNoAppLaunchUrl = new ClientMetadata();
            clientMetadataNoAppLaunchUrl.setClientId("client-4");
            clientMetadataNoAppLaunchUrl.setShowOnHomePage(true);

            List<ClientMetadata> clientMetadataList = new ArrayList<>();
            clientMetadataList.add(clientMetadata1);
            clientMetadataList.add(clientMetadata2);
            clientMetadataList.add(clientMetadataDoesNotExist);
            clientMetadataList.add(clientMetadataNoAppLaunchUrl);

            JdbcClientMetadataProvisioning clientMetadata = mock(JdbcClientMetadataProvisioning.class);
            when(clientMetadata.retrieveAll(anyString())).thenReturn(clientMetadataList);
            return clientMetadata;
        }

        @Bean
        HomeController homeController(
                final JdbcClientMetadataProvisioning clientMetadataProvisioning,
                final BuildInfo buildInfo) {
            return new HomeController(
                    clientMetadataProvisioning,
                    buildInfo,
                    null);
        }
    }
}
