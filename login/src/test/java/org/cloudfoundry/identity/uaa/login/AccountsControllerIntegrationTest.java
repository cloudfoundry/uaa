package org.cloudfoundry.identity.uaa.login;

import com.dumbster.smtp.SimpleSmtpServer;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.login.test.UaaRestTemplateBeanFactoryPostProcessor;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

public class AccountsControllerIntegrationTest {

    XmlWebApplicationContext webApplicationContext;

    private MockMvc mockMvc;
    private MockRestServiceServer mockUaaServer;
    private static SimpleSmtpServer mailServer;

    @BeforeClass
    public static void startMailServer() throws Exception {
        mailServer = SimpleSmtpServer.start(2525);
    }

    @Before
    public void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setEnvironment(new MockEnvironment());
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:../uaa/src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.addBeanFactoryPostProcessor(new UaaRestTemplateBeanFactoryPostProcessor());
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();

        mockUaaServer = MockRestServiceServer.createServer(webApplicationContext.getBean("authorizationTemplate", RestTemplate.class));
    }

    @AfterClass
    public static void stopMailServer() throws Exception {
        mailServer.stop();
    }

    @Test
    public void testCreateActivationEmailPage() throws Exception {
        ((MockEnvironment) webApplicationContext.getEnvironment()).setProperty("login.brand", "oss");

        mockMvc.perform(get("/create_account.do"))
                .andExpect(content().string(containsString("Create your account")))
                .andExpect(content().string(not(containsString("Pivotal ID"))));
    }

    @Test
    public void testCreateActivationEmailPageWithPivotalBrand() throws Exception {
        ((MockEnvironment) webApplicationContext.getEnvironment()).setProperty("login.brand", "pivotal");

        mockMvc.perform(get("/create_account.do"))
            .andExpect(content().string(containsString("Create your Pivotal ID")))
            .andExpect(content().string(not(containsString("Create your account"))));
    }

    @Test
    public void testActivationEmailSentPage() throws Exception {
        ((MockEnvironment) webApplicationContext.getEnvironment()).setProperty("login.brand", "oss");

        mockMvc.perform(get("/accounts/email_sent"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Create your account")))
                .andExpect(xpath("//input[@disabled='disabled']/@value").string("Email successfully sent"))
                .andExpect(content().string(not(containsString("Pivotal ID"))));
    }

    @Test
    public void testActivationEmailSentPageWithPivotalBrand() throws Exception {
        ((MockEnvironment) webApplicationContext.getEnvironment()).setProperty("login.brand", "pivotal");

        mockMvc.perform(get("/accounts/email_sent"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Create your Pivotal ID")))
                .andExpect(xpath("//input[@disabled='disabled']/@value").string("Email successfully sent"))
                .andExpect(content().string(not(containsString("Create your account"))));
    }

    @Test
    public void testCreatingAnAccount() throws Exception {
        String scimUserJSONString = "{" +
            "\"userName\": \"user@example.com\"," +
            "\"id\": \"newly-created-user-id\"," +
            "\"emails\": [{\"value\":\"user@example.com\"}]" +
            "}";
        mockUaaServer.expect(requestTo("http://localhost:8080/uaa/Users"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.userName").value("user@example.com"))
            .andExpect(jsonPath("$.password").value("secret"))
            .andExpect(jsonPath("$.origin").value("uaa"))
            .andExpect(jsonPath("$.verified").value(false))
            .andExpect(jsonPath("$.emails[0].value").value("user@example.com"))
            .andRespond(withSuccess(scimUserJSONString, APPLICATION_JSON));

        mockUaaServer.expect(requestTo("http://localhost:8080/uaa/Codes"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess("{\"code\":\"the_secret_code\"," +
                                "\"expiresAt\":1406152741265," +
                                "\"data\":\"{\\\"user_id\\\":\\\"newly-created-user-id\\\",\\\"client_id\\\":\\\"app\\\"}\"}",
                        APPLICATION_JSON));

        String uaaResponseJson = "{" +
            "    \"code\":\"the_secret_code\"," +
            "    \"expiresAt\":1406152741265," +
            "    \"data\":\"{\\\"user_id\\\":\\\"newly-created-user-id\\\",\\\"client_id\\\":\\\"app\\\"}\"" +
            "}";
        mockUaaServer.expect(requestTo("http://localhost:8080/uaa/Codes/the_secret_code"))
            .andExpect(method(GET))
            .andRespond(withSuccess(uaaResponseJson, APPLICATION_JSON));

        mockUaaServer.expect(requestTo("http://localhost:8080/uaa/Users/newly-created-user-id/verify"))
            .andExpect(method(GET))
            .andRespond(withSuccess(scimUserJSONString, APPLICATION_JSON));

        Map<String,Object> additionalInformation = new HashMap<>();
        additionalInformation.put("signup_redirect_url", "http://example.com/redirect");

        String clientDetails = "{" +
            "\"client_id\": \"app\"," +
            "\"signup_redirect_url\": \"http://example.com/redirect\"" +
            "}";
        mockUaaServer.expect(requestTo("http://localhost:8080/uaa/oauth/clients/app"))
            .andExpect(method(GET))
            .andRespond(withSuccess(clientDetails, APPLICATION_JSON));

        mockMvc.perform(post("/create_account.do")
                    .param("email", "user@example.com")
                    .param("password", "secret")
                    .param("password_confirmation", "secret")
                    .param("client_id", "app"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        MvcResult mvcResult = mockMvc.perform(get("/verify_user")
                .param("code", "the_secret_code"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://example.com/redirect"))
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        Assert.assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        Assert.assertThat(principal.getId(), equalTo("newly-created-user-id"));
        Assert.assertThat(principal.getEmail(), equalTo("user@example.com"));
        Assert.assertThat(principal.getOrigin(), equalTo(Origin.UAA));
    }
}