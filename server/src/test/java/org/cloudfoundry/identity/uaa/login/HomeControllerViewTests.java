package org.cloudfoundry.identity.uaa.login;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.client.ClientMetadata;
import org.cloudfoundry.identity.uaa.client.JdbcClientMetadataProvisioning;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.home.HomeController;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = HomeControllerViewTests.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class HomeControllerViewTests extends TestClassNullifier {

    private static final String base64EncodedImg = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAXRQTFRFAAAAOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ozk4Ojo6Ojk5NkZMFp/PFqDPNkVKOjo6Ojk5MFhnEq3nEqvjEqzjEbDpMFdlOjo5Ojo6Ojo6Ozg2GZ3TFqXeFKfgF6DVOjo6Ozg2G5jPGZ7ZGKHbGZvROjo6Ojo5M1FfG5vYGp3aM1BdOjo6Ojo6Ojk4KHWeH5PSHpTSKHSbOjk4Ojo6Ojs8IY/QIY/QOjs7Ojo6Ojo6Ozc0JYfJJYjKOzYyOjo5Ozc0KX7AKH/AOzUxOjo5Ojo6Ojo6Ojo6Ojs8LHi6LHi6Ojs7Ojo6Ojo6Ojo6Ojo6Ojo6L3K5L3S7LnW8LnS7Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6NlFvMmWeMmaeNVJwOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojk5Ojk4Ojk4Ojk5Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6FaXeFabfGZ/aGKDaHJnVG5rW////xZzURgAAAHV0Uk5TAAACPaXbAVzltTa4MykoM5HlPY/k5Iw85QnBs2D7+lzAtWD7+lyO6EKem0Ey47Mx2dYvtVZVop5Q2i4qlZAnBiGemh0EDXuddqypcHkShPJwYufmX2rvihSJ+qxlg4JiqP2HPtnW1NjZ2svRVAglGTi91RAXr3/WIQAAAAFiS0dEe0/StfwAAAAJcEhZcwAAAEgAAABIAEbJaz4AAADVSURBVBjTY2BgYGBkYmZhZWVhZmJkAANGNnYODk5ODg52NrAIIyMXBzcPLx8/NwcXIyNYQEBQSFhEVExcQgAiICklLSNbWiYnLy0lCRFQUFRSLq9QUVVUgAgwqqlraFZWaWmrqzFCTNXR1dM3MDQy1tWB2MvIaMJqamZuYWnCCHeIlbWNrZ0VG5QPFLF3cHRydoErcHVz9/D08nb3kYSY6evnHxAYFBwSGhYeAbbWNzIqOiY2Lj4hMckVoiQ5JTUtPSMzKzsH6pfcvPyCwqKc4pJcoAAA2pghnaBVZ0kAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTUtMTAtMDhUMTI6NDg6MDkrMDA6MDDsQS6eAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE1LTEwLTA4VDEyOjQ4OjA5KzAwOjAwnRyWIgAAAEZ0RVh0c29mdHdhcmUASW1hZ2VNYWdpY2sgNi43LjgtOSAyMDE0LTA1LTEyIFExNiBodHRwOi8vd3d3LmltYWdlbWFnaWNrLm9yZ9yG7QAAAAAYdEVYdFRodW1iOjpEb2N1bWVudDo6UGFnZXMAMaf/uy8AAAAYdEVYdFRodW1iOjpJbWFnZTo6aGVpZ2h0ADE5Mg8AcoUAAAAXdEVYdFRodW1iOjpJbWFnZTo6V2lkdGgAMTky06whCAAAABl0RVh0VGh1bWI6Ok1pbWV0eXBlAGltYWdlL3BuZz+yVk4AAAAXdEVYdFRodW1iOjpNVGltZQAxNDQ0MzA4NDg5qdC9PQAAAA90RVh0VGh1bWI6OlNpemUAMEJClKI+7AAAAFZ0RVh0VGh1bWI6OlVSSQBmaWxlOi8vL21udGxvZy9mYXZpY29ucy8yMDE1LTEwLTA4LzJiMjljNmYwZWRhZWUzM2ViNmM1Mzg4ODMxMjg3OTg1Lmljby5wbmdoJKG+AAAAAElFTkSuQmCC";

    @Autowired
    WebApplicationContext webApplicationContext;

    @Autowired
    MockEnvironment environment;

    private MockMvc mockMvc;

    private IdentityZoneConfiguration originalConfiguration;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .build();
        originalConfiguration = IdentityZoneHolder.get().getConfig();
        IdentityZoneHolder.get().setConfig(new IdentityZoneConfiguration());
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        IdentityZoneHolder.get().setConfig(originalConfiguration);
    }

    @Test
    @Ignore
    public void tilesFromClientMetadataAndTilesConfigShown() throws Exception {
        mockMvc.perform(get("/"))
            .andExpect(xpath("//*[@id='tile-1'][text()[contains(.,'client-1')]]").exists())
            .andExpect(xpath("//*[@class='tile-1']/@href").string("http://app.launch/url"))

            .andExpect(xpath("//head/style[2]").string(".tile-1 .tile-icon {background-image: url(\"data:image/png;base64," + base64EncodedImg + "\")}"))
            .andExpect(xpath("//*[@id='tile-2'][text()[contains(.,'Client 2 Name')]]").exists())
            .andExpect(xpath("//*[@class='tile-2']/@href").string("http://second.url/"))

            .andExpect(xpath("//*[@class='tile-3']").doesNotExist());
    }

    @Ignore
    @Test
    public void tilesFromClientMetadataAndTilesConfigShown_forOtherZone() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone("test", "test");
        IdentityZoneHolder.set(identityZone);
        mockMvc.perform(get("/"))
          .andExpect(xpath("//*[@id='tile-1'][text()[contains(.,'client-1')]]").exists())
          .andExpect(xpath("//*[@class='tile-1']/@href").string("http://app.launch/url"))

          .andExpect(xpath("//head/style[2]").string(".tile-1 .tile-icon {background-image: url(\"data:image/png;base64," + base64EncodedImg + "\")}"))
          .andExpect(xpath("//*[@id='tile-2'][text()[contains(.,'Client 2 Name')]]").exists())
          .andExpect(xpath("//*[@class='tile-2']/@href").string("http://second.url/"))

          .andExpect(xpath("//*[@class='tile-3']").doesNotExist());
    }

    @Test
    public void testConfiguredHomePage() throws Exception {
        mockMvc.perform(get("/home"))
            .andExpect(status().isOk());

        String customHomePage = "http://custom.home/page";
        IdentityZoneHolder.get().getConfig().getLinks().setHomeRedirect(customHomePage);
        mockMvc.perform(get("/home"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", customHomePage));

        IdentityZone zone = MultitenancyFixture.identityZone("zone","zone");
        zone.setConfig(new IdentityZoneConfiguration());
        IdentityZoneHolder.set(zone);
        mockMvc.perform(get("/home"))
            .andExpect(status().isOk());

        zone.getConfig().getLinks().setHomeRedirect(customHomePage);
        mockMvc.perform(get("/home"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", customHomePage));
    }

    @Configuration
    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration extends WebMvcConfigurerAdapter {

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Bean
        BuildInfo buildInfo() {
            return new BuildInfo();
        }

        @Bean
        JdbcClientMetadataProvisioning clientMetadataProvisioning() throws MalformedURLException {
            ClientMetadata clientMetadata1 = new ClientMetadata();
            clientMetadata1.setClientId("client-1");
            clientMetadata1.setShowOnHomePage(true);
            clientMetadata1.setAppLaunchUrl(new URL("http://app.launch/url"));
            clientMetadata1.setAppIcon(base64EncodedImg);

            ClientMetadata clientMetadata2 = new ClientMetadata();
            clientMetadata2.setClientId("client-2");
            clientMetadata2.setShowOnHomePage(true);
            clientMetadata2.setAppLaunchUrl(new URL("http://second.url/"));
            clientMetadata2.setAppIcon("base64-encoded-img");
            clientMetadata2.setClientName("Client 2 Name");

            ClientMetadata clientMetadataDoesNotExist = new ClientMetadata();
            clientMetadataDoesNotExist.setClientId("client-3");
            clientMetadataDoesNotExist.setShowOnHomePage(false);

            List<ClientMetadata> clientMetadataList = new ArrayList<>();
            clientMetadataList.add(clientMetadata1);
            clientMetadataList.add(clientMetadata2);
            clientMetadataList.add(clientMetadataDoesNotExist);

            JdbcClientMetadataProvisioning clientMetadata = mock(JdbcClientMetadataProvisioning.class);
            when(clientMetadata.retrieveAll()).thenReturn(clientMetadataList);
            return clientMetadata;
        }

        @Bean
        MockEnvironment environment() {
            return new MockEnvironment();
        }

        @Bean
        HomeController homeController(MockEnvironment environment) {
            HomeController homeController = new HomeController(environment);
            homeController.setUaaBaseUrl("http://uaa.example.com");
            return homeController;
        }
    }
}
