package org.cloudfoundry.identity.uaa.mock;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.flywaydb.core.Flyway;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.springframework.restdocs.JUnitRestDocumentation;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import static org.junit.Assume.assumeTrue;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.templates.TemplateFormats.markdown;

public class InjectedMockContextTest implements Contextable {

    protected RandomValueStringGenerator generator = new RandomValueStringGenerator(12) {
        @Override
        public String generate() {
            return super.generate().toLowerCase();
        }
    };

    @ClassRule
    public static SkipWhenNotRunningInSuiteRule skip = new SkipWhenNotRunningInSuiteRule();

    @Rule
    public JUnitRestDocumentation restDocumentation = new JUnitRestDocumentation("build/generated-snippets");

    protected static RandomValueStringGenerator gen = new RandomValueStringGenerator(8);

    private static XmlWebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    protected TestClient testClient;
    private static volatile boolean mustDestroy = false;

    public static XmlWebApplicationContext getWebApplicationContext() {
        if (webApplicationContext == null) {
            webApplicationContext = DefaultConfigurationTestSuite.setUpContext();
            mustDestroy = true;
        }

        return webApplicationContext;
    }

    public MockMvc getMockMvc() {
        return mockMvc;
    }

    private static boolean isMustDestroy() {
        return mustDestroy;
    }

    @Before
    public void initMockMvc() {
        FilterChainProxy springSecurityFilterChain = getWebApplicationContext().getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(getWebApplicationContext())
                .addFilter(springSecurityFilterChain)
                .apply(documentationConfiguration(this.restDocumentation)
                        .uris().withPort(80).and()
                        .snippets()
                        .withTemplateFormat(markdown()))
                .build();

        testClient = new TestClient(mockMvc);
    }

    @AfterClass
    public static void mustDestroy() {
        if (isMustDestroy() && webApplicationContext != null) {
            webApplicationContext.getBean(Flyway.class).clean();
            webApplicationContext.destroy();
        }
        webApplicationContext = null;
        mustDestroy = false;
    }

    @Override
    public void inject(XmlWebApplicationContext context) {
        webApplicationContext = context;
    }

    public TestClient getTestClient() {
        return testClient;
    }

    public static class SkipWhenNotRunningInSuiteRule implements TestRule {
        @Override
        public Statement apply(Statement statement, Description description) {
            assumeTrue(UaaBaseSuite.shouldMockTestBeRun());
            return statement;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OAuthToken {
        @JsonProperty("access_token")
        public String accessToken;

        public OAuthToken() {
        }
    }

}
