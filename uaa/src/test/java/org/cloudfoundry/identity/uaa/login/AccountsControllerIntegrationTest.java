package org.cloudfoundry.identity.uaa.login;

import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;
import static org.springframework.util.StringUtils.isEmpty;
import com.dumbster.smtp.SimpleSmtpServer;
import com.dumbster.smtp.SmtpMessage;
import com.googlecode.flyway.core.Flyway;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.login.test.MockMvcTestClient;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneCreationRequest;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

public class AccountsControllerIntegrationTest {

    XmlWebApplicationContext webApplicationContext;

    private MockMvc mockMvc;
    private static SimpleSmtpServer mailServer;
    private String userEmail;
    private MockMvcTestClient mockMvcTestClient;

    @BeforeClass
    public static void startMailServer() throws Exception {
        mailServer = SimpleSmtpServer.start(2525);
    }

    @Before
    public void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("smtp.host", "localhost");
        environment.setProperty("smtp.port", "2525");
        webApplicationContext.setEnvironment(environment);
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();

        userEmail = "user" +new RandomValueStringGenerator().generate()+ "@example.com";
        Assert.assertNotNull(webApplicationContext.getBean("messageService"));

        mockMvcTestClient = new MockMvcTestClient(mockMvc);

        for (Iterator i = mailServer.getReceivedEmail(); i.hasNext();) {
            i.next();
            i.remove();
        }
    }

    @After
    public void tearDown() throws Exception {
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
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
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        mockMvc.perform(post("/create_account.do")
                .param("email", userEmail)
                .param("password", "secret")
                .param("password_confirmation", "secret"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        MvcResult mvcResult = mockMvc.perform(get("/verify_user")
                .param("code", "test"+generator.counter.get()))
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("home"))
                .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        Assert.assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        Assert.assertThat(principal.getEmail(), equalTo(userEmail));
        Assert.assertThat(principal.getOrigin(), equalTo(Origin.UAA));
    }

    @Test
    public void testCreatingAnAccountWithAnEmptyClientId() throws Exception {
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        mockMvc.perform(post("/create_account.do")
                .param("email", userEmail)
                .param("password", "secret")
                .param("password_confirmation", "secret")
                .param("client_id", ""))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        MvcResult mvcResult = mockMvc.perform(get("/verify_user")
                .param("code", "test"+generator.counter.get()))
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("home"))
                .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        Assert.assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        Assert.assertThat(principal.getEmail(), equalTo(userEmail));
        Assert.assertThat(principal.getOrigin(), equalTo(Origin.UAA));
    }

    @Test
    public void testCreatingAnAccountWithClientRedirect() throws Exception {
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        mockMvc.perform(post("/create_account.do")
                    .param("email", userEmail)
                    .param("password", "secret")
                    .param("password_confirmation", "secret")
                    .param("client_id", "app"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        Iterator receivedEmail = mailServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        assertTrue(message.getBody().contains("Cloud Foundry"));
        assertTrue(message.getHeaderValue("From").contains("Cloud Foundry"));

        MvcResult mvcResult = mockMvc.perform(get("/verify_user")
                .param("code", "test"+generator.counter.get()))
            .andDo(print())
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost:8080/app/"))
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        Assert.assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        Assert.assertThat(principal.getEmail(), equalTo(userEmail));
        Assert.assertThat(principal.getOrigin(), equalTo(Origin.UAA));
    }

    @Test
    public void testCreatingAnAccountInAnotherZoneWithNoClientRedirect() throws Exception {
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain("mysubdomain");
        identityZone.setName("myzonename");
        identityZone.setId(new RandomValueStringGenerator().generate());

        IdentityZoneCreationRequest zoneCreationRequest = new IdentityZoneCreationRequest();
        zoneCreationRequest.setIdentityZone(identityZone);

        String zonesCreateToken = mockMvcTestClient.getOAuthAccessToken("identity", "identitysecret", "client_credentials", "zones.create");
        mockMvc.perform(post("/identity-zones")
                .header("Authorization", "Bearer " + zonesCreateToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(zoneCreationRequest)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/create_account.do")
                .with(new SetServerNameRequestPostProcessor("mysubdomain.localhost"))
                .param("email", userEmail)
                .param("password", "secret")
                .param("password_confirmation", "secret"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        Iterator receivedEmail = mailServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        String link = mockMvcTestClient.extractLink(message.getBody());
        assertTrue(message.getBody().contains("myzonename"));
        assertTrue(message.getHeaderValue("From").contains("myzonename"));
        assertFalse(message.getBody().contains("Cloud Foundry"));
        assertFalse(message.getBody().contains("Pivotal"));
        assertFalse(isEmpty(link));
        assertTrue(link.contains("mysubdomain.localhost"));

        MvcResult mvcResult = mockMvc.perform(get("/verify_user")
                .param("code", "test" + generator.counter.get())
                .with(new SetServerNameRequestPostProcessor("mysubdomain.localhost")))
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("home"))
                .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        Assert.assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        Assert.assertThat(principal.getEmail(), equalTo(userEmail));
        Assert.assertThat(principal.getOrigin(), equalTo(Origin.UAA));
    }

    @Test
    public void testCreatingAnAccountInAnotherZoneWithClientRedirect() throws Exception {
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain("mysubdomain");
        identityZone.setName("myzonename");
        identityZone.setId(new RandomValueStringGenerator().generate());

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("myzoneclient");
        clientDetails.setClientSecret("myzoneclientsecret");
        clientDetails.setAuthorizedGrantTypes(Arrays.asList("client_credentials"));
        clientDetails.addAdditionalInformation("signup_redirect_url", "http://myzoneclient.example.com");

        IdentityZoneCreationRequest zoneCreationRequest = new IdentityZoneCreationRequest();
        zoneCreationRequest.setIdentityZone(identityZone);
        zoneCreationRequest.setClientDetails(Arrays.asList(clientDetails));

        String zonesCreateToken = mockMvcTestClient.getOAuthAccessToken("identity", "identitysecret", "client_credentials", "zones.create");
        mockMvc.perform(post("/identity-zones")
                    .header("Authorization", "Bearer " + zonesCreateToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(new ObjectMapper().writeValueAsString(zoneCreationRequest)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/create_account.do")
                    .with(new SetServerNameRequestPostProcessor("mysubdomain.localhost"))
                    .param("email", userEmail)
                    .param("password", "secret")
                    .param("password_confirmation", "secret")
                    .param("client_id", "myzoneclient"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        Iterator receivedEmail = mailServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        String link = mockMvcTestClient.extractLink(message.getBody());
        assertFalse(isEmpty(link));
        assertTrue(link.contains("mysubdomain.localhost"));

        MvcResult mvcResult = mockMvc.perform(get("/verify_user")
                    .param("code", "test" + generator.counter.get())
                    .with(new SetServerNameRequestPostProcessor("mysubdomain.localhost")))
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://myzoneclient.example.com"))
                .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        Assert.assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        Assert.assertThat(principal.getEmail(), equalTo(userEmail));
        Assert.assertThat(principal.getOrigin(), equalTo(Origin.UAA));
    }

    public static class PredictableGenerator extends RandomValueStringGenerator {
        public AtomicInteger counter = new AtomicInteger(1);
        @Override
        public String generate() {
            return  "test"+counter.incrementAndGet();
        }
    }
}