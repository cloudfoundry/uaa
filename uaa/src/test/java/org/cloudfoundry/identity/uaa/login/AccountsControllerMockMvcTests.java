package org.cloudfoundry.identity.uaa.login;

import com.dumbster.smtp.SimpleSmtpServer;
import com.dumbster.smtp.SmtpMessage;
import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.account.EmailAccountCreationService;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.test.MockMvcTestClient;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.PredictableGenerator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.*;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Collections;
import java.util.Iterator;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.util.StringUtils.isEmpty;

public class AccountsControllerMockMvcTests extends InjectedMockContextTest {

    private static SimpleSmtpServer mailServer;
    private final String LOGIN_REDIRECT = "/login?success=verify_success";
    private final String USER_PASSWORD = "secr3T";
    private String userEmail;
    private MockMvcTestClient mockMvcTestClient;
    private JavaMailSender originalSender;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    @BeforeClass
    public static void startMailServer() {
        mailServer = SimpleSmtpServer.start(2525);
    }

    @Before
    public void setUp() throws Exception {
        originalSender = getWebApplicationContext().getBean("emailService", EmailService.class).getMailSender();

        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("localhost");
        mailSender.setPort(2525);
        getWebApplicationContext().getBean("emailService", EmailService.class).setMailSender(mailSender);

        userEmail = "user" +new RandomValueStringGenerator().generate()+ "@example.com";
        Assert.assertNotNull(getWebApplicationContext().getBean("messageService"));

        mockMvcTestClient = new MockMvcTestClient(getMockMvc());

        for (Iterator i = mailServer.getReceivedEmail(); i.hasNext();) {
            i.next();
            i.remove();
        }
    }

    @After
    public void restoreMailSender() {
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("assetBaseUrl", "/resources/oss");
        getWebApplicationContext().getBean("emailService", EmailService.class).setMailSender(originalSender);
    }

    @After
    public void resetGenerator() {
        getWebApplicationContext().getBean(JdbcExpiringCodeStore.class).setGenerator(new RandomValueStringGenerator(24));
    }


    @AfterClass
    public static void stopMailServer() {
        if (mailServer!=null) {
            mailServer.stop();
        }
    }

    @Test
    public void testCreateActivationEmailPage() throws Exception {
        getMockMvc().perform(get("/create_account"))
                .andExpect(content().string(containsString("Create your account")));
    }

    @Test
    public void testCreateActivationEmailPageWithinZone() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        getMockMvc().perform(get("/create_account")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
            .andExpect(content().string(containsString("Create your account")));
    }

    @Test
    public void testActivationEmailSentPage() throws Exception {
        getMockMvc().perform(get("/accounts/email_sent"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Create your account")))
                .andExpect(xpath("//input[@disabled='disabled']/@value").string("Email successfully sent"));
    }

    @Test
    public void testActivationEmailSentPageWithinZone() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        getMockMvc().perform(get("/accounts/email_sent")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Create your account")))
            .andExpect(xpath("//input[@disabled='disabled']/@value").string("Email successfully sent"))
            .andExpect(content().string(containsString("Cloud Foundry")));
    }

    @Test
    public void testPageTitle() throws Exception {
        getMockMvc().perform(get("/create_account"))
            .andExpect(content().string(containsString("<title>Cloud Foundry</title>")));
    }

    @Test
    public void testPageTitleWithinZone() throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        getMockMvc().perform(get("/create_account")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
            .andExpect(content().string(containsString("<title>" + zone.getName() + "</title>")));
    }

    @Test
    public void testCreateAccountWithdisableSelfService() throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        zone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(false);

        MockMvcUtils.createOtherIdentityZoneAndReturnResult(getMockMvc(), getWebApplicationContext(), getBaseClientDetails() ,zone);

        getMockMvc().perform(get("/create_account")
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
                .andExpect(model().attribute("error_message_code", "self_service_disabled"))
                .andExpect(view().name("error"))
                .andExpect(status().isNotFound());
    }

    @Test
    public void testDisableSelfServiceCreateAccountPost() throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        zone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(false);

        MockMvcUtils.createOtherIdentityZoneAndReturnResult(getMockMvc(), getWebApplicationContext(), getBaseClientDetails() ,zone);

        getMockMvc().perform(post("/create_account.do")
                                 .with(cookieCsrf())
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param("email", userEmail)
                .param("password", "secr3T")
                .param("password_confirmation", "secr3T"))
                .andExpect(model().attribute("error_message_code", "self_service_disabled"))
                .andExpect(view().name("error"))
                .andExpect(status().isNotFound());
    }

    @Test
    public void defaultZoneLogoNull_useAssetBaseUrlImage() throws Exception {
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("assetBaseUrl", "/resources/oss");

        getMockMvc().perform(get("/create_account"))
            .andExpect(content().string(containsString("background-image: url(/resources/oss/images/product-logo.png);")));
    }

    @Test
    public void zoneLogoNull_doNotDisplayImage() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("assetBaseUrl", "/resources/oss");

        getMockMvc().perform(get("/create_account")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
            .andExpect(content().string(not(containsString("background-image: url(/resources/oss/images/product-logo.png);"))));
    }

    @Test
    public void testCreatingAnAccount() throws Exception {
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        getMockMvc().perform(post("/create_account.do")
                                 .with(cookieCsrf())
            .param("email", userEmail)
            .param("password", "secr3T")
            .param("password_confirmation", "secr3T"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        JdbcScimUserProvisioning scimUserProvisioning = getWebApplicationContext().getBean(JdbcScimUserProvisioning.class);
        ScimUser scimUser = scimUserProvisioning.query("userName eq '" + userEmail + "' and origin eq '" + OriginKeys.UAA + "'", IdentityZoneHolder.get().getId()).get(0);
        assertFalse(scimUser.isVerified());

        getMockMvc().perform(get("/verify_user")
            .param("code", "test" + generator.counter.get()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT))
                .andReturn();

        MvcResult mvcResult = loginWithAccount("")
            .andExpect(authenticated())
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail(), equalTo(userEmail));
        assertThat(principal.getOrigin(), equalTo(OriginKeys.UAA));
    }

    @Test
    public void testCreatingAnAccountWithAnEmptyClientId() throws Exception {
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        getMockMvc().perform(post("/create_account.do")
                                 .with(cookieCsrf())
            .param("email", userEmail)
            .param("password", "secr3T")
            .param("password_confirmation", "secr3T")
            .param("client_id", ""))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        getMockMvc().perform(get("/verify_user")
            .param("code", "test" + generator.counter.get()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT))
                .andReturn();

        MvcResult mvcResult = loginWithAccount("")
            .andExpect(authenticated())
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail(), equalTo(userEmail));
        assertThat(principal.getOrigin(), equalTo(OriginKeys.UAA));
    }

    @Test
    public void testCreatingAnAccountWithClientRedirect() throws Exception {
        createAccount("http://redirect.uri/client", "http://redirect.uri/client");
    }

    @Test
    public void testCreatingAnAccountWithFallbackClientRedirect() throws Exception {
        createAccount("http://redirect.uri/fallback", null);
    }

    @Test
    public void testCreatingAnAccountWithNoClientRedirect() throws Exception {
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        getMockMvc().perform(post("/create_account.do")
                                 .with(cookieCsrf())
            .param("email", userEmail)
            .param("password", "secr3T")
            .param("password_confirmation", "secr3T"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("accounts/email_sent"));

        Iterator receivedEmail = mailServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        assertTrue(message.getBody().contains("Cloud Foundry"));
        assertTrue(message.getHeaderValue("From").contains("Cloud Foundry"));

        getMockMvc().perform(get("/verify_user")
            .param("code", "test" + generator.counter.get()))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(LOGIN_REDIRECT))
            .andReturn();

        MvcResult mvcResult = loginWithAccount("")
            .andExpect(authenticated())
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail(), equalTo(userEmail));
        assertThat(principal.getOrigin(), equalTo(OriginKeys.UAA));
    }

    @Test
    public void testCreatingAnAccountInAnotherZoneWithNoClientRedirect() throws Exception {
        String subdomain = "mysubdomain2";
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(subdomain);
        identityZone.setName(subdomain+"zone");
        identityZone.setId(new RandomValueStringGenerator().generate());

        String zonesCreateToken = mockMvcTestClient.getOAuthAccessToken("identity", "identitysecret", "client_credentials", "zones.write");
        getMockMvc().perform(post("/identity-zones")
            .header("Authorization", "Bearer " + zonesCreateToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated());

        getMockMvc().perform(post("/create_account.do")
                                 .with(cookieCsrf())
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("email", userEmail)
            .param("password", USER_PASSWORD)
            .param("password_confirmation", USER_PASSWORD))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        Iterator receivedEmail = mailServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        String link = mockMvcTestClient.extractLink(message.getBody());
        assertTrue(message.getBody().contains(subdomain+"zone"));
        assertTrue(message.getHeaderValue("From").contains(subdomain+"zone"));
        assertFalse(message.getBody().contains("Cloud Foundry"));
        assertFalse(message.getBody().contains("Pivotal"));
        assertFalse(isEmpty(link));
        assertTrue(link.contains(subdomain+".localhost"));

        getMockMvc().perform(get("/verify_user")
            .param("code", "test" + generator.counter.get())
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT))
                .andReturn();

        MvcResult mvcResult = loginWithAccount(subdomain)
            .andExpect(redirectedUrl("/"))
            .andExpect(authenticated())
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail(), equalTo(userEmail));
        assertThat(principal.getOrigin(), equalTo(OriginKeys.UAA));
    }

    @Test
    public void testCreatingAnAccountInAnotherZoneWithClientRedirect() throws Exception {
        String subdomain = "mysubdomain1";
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(subdomain);
        identityZone.setName(subdomain);
        identityZone.setId(new RandomValueStringGenerator().generate());

        MockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext(), getBaseClientDetails());

        getMockMvc().perform(post("/create_account.do")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                                 .with(cookieCsrf())
            .param("email", userEmail)
            .param("password", "secr3T")
            .param("password_confirmation", "secr3T")
            .param("client_id", "myzoneclient")
            .param("redirect_uri", "http://myzoneclient.example.com"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("accounts/email_sent"));

        Iterator receivedEmail = mailServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        String link = mockMvcTestClient.extractLink(message.getBody());
        assertFalse(isEmpty(link));
        assertTrue(link.contains(subdomain+".localhost"));

        getMockMvc().perform(get("/verify_user")
            .param("code", "test" + generator.counter.get())
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
                .andExpect(redirectedUrl(LOGIN_REDIRECT + "&form_redirect_uri=http://myzoneclient.example.com"))
                .andReturn();

        MvcResult mvcResult = loginWithAccount(subdomain)
            .andExpect(authenticated())
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail(), equalTo(userEmail));
        assertThat(principal.getOrigin(), equalTo(OriginKeys.UAA));
    }

    private BaseClientDetails getBaseClientDetails() {
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("myzoneclient");
        clientDetails.setClientSecret("myzoneclientsecret");
        clientDetails.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
        clientDetails.setRegisteredRedirectUri(Collections.singleton("http://myzoneclient.example.com"));
        return clientDetails;
    }

    @Test
    public void redirectToSavedRequest_ifPresent() throws Exception {
        MockHttpSession session = MockMvcUtils.getSavedRequestSession();

        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        getMockMvc().perform(post("/create_account.do")
            .with(cookieCsrf())
                .session(session)
                .param("email", "testuser@test.org")
                .param("password", "test-password")
                .param("password_confirmation", "test-password"))
                .andExpect(redirectedUrl("accounts/email_sent"));

        getMockMvc().perform(get("/verify_user")
                .session(session)
                .param("code", "test" + generator.counter.get()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT))
                .andReturn();

        assertNotNull(((SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE)).getRedirectUrl());
    }

    @Test
    public void ifInvalidOrExpiredCode_goTo_createAccountDefaultPage() throws Exception {
        getMockMvc().perform(get("/verify_user")
            .param("code", "expired-code"))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "code_expired"))
            .andExpect(view().name("accounts/link_prompt"))
            .andExpect(xpath("//a[text()='here']/@href").string("/create_account"));
    }

    @Test
    public void ifInvalidOrExpiredCode_withNonDefaultSignupLinkProperty_goToNonDefaultSignupPage() throws Exception {
        String signUpLink = "http://mypage.com/signup";
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("links.signup", signUpLink);

        getMockMvc().perform(get("/verify_user")
            .param("code", "expired-code"))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "code_expired"))
            .andExpect(view().name("accounts/link_prompt"))
            .andExpect(xpath("//a[text()='here']/@href").string(signUpLink));
    }

    @Test
    public void testConsentIfConfigured_displaysConsentTextAndLink() throws Exception {
        String randomZoneSubdomain = generator.generate();
        String consentText = "Terms and Conditions";
        String consentLink = "http://google.com";
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(
            randomZoneSubdomain, getMockMvc(), getWebApplicationContext());

        zone.getConfig().setBranding(new BrandingInformation());
        zone.getConfig().getBranding().setConsent(new Consent());
        zone.getConfig().getBranding().getConsent().setText(consentText);
        zone.getConfig().getBranding().getConsent().setLink(consentLink);
        MockMvcUtils.updateZone(getMockMvc(), zone);

        getMockMvc().perform(get("/create_account")
            .with(new SetServerNameRequestPostProcessor(randomZoneSubdomain + ".localhost")))
            .andExpect(content().string(containsString(consentText)))
            .andExpect(content().string(containsString(consentLink)));
    }

    @Test
    public void testConsentIfConfigured_displayConsentTextWhenNoLinkConfigured() throws Exception {
        String randomZoneSubdomain = generator.generate();
        String consentText = "Terms and Conditions";
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(
            randomZoneSubdomain, getMockMvc(), getWebApplicationContext());

        zone.getConfig().setBranding(new BrandingInformation());
        zone.getConfig().getBranding().setConsent(new Consent());
        zone.getConfig().getBranding().getConsent().setText(consentText);
        MockMvcUtils.updateZone(getMockMvc(), zone);

        getMockMvc().perform(get("/create_account")
            .with(new SetServerNameRequestPostProcessor(randomZoneSubdomain + ".localhost")))
            .andExpect(content().string(containsString(consentText)));
    }

    @Test
    public void testConsentIfConfigured_displaysMeaningfulErrorWhenConsentNotProvided() throws Exception {
        String randomZoneSubdomain = generator.generate();
        String consentText = "Terms and Conditions";
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(
            randomZoneSubdomain, getMockMvc(), getWebApplicationContext());

        zone.getConfig().setBranding(new BrandingInformation());
        zone.getConfig().getBranding().setConsent(new Consent());
        zone.getConfig().getBranding().getConsent().setText(consentText);
        MockMvcUtils.updateZone(getMockMvc(), zone);

        getMockMvc().perform(post("/create_account.do")
            .with(new SetServerNameRequestPostProcessor(randomZoneSubdomain + ".localhost"))
            .with(cookieCsrf())
            .param("email", userEmail)
            .param("password", USER_PASSWORD)
            .param("password_confirmation", USER_PASSWORD)
            .param("does_user_consent", "false"))
            .andExpect(content().string(containsString("Please agree before continuing.")));
    }

    private BaseClientDetails createTestClient() throws Exception {
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("test-client-" + RandomStringUtils.randomAlphanumeric(200));
        clientDetails.setClientSecret("test-client-secret");
        clientDetails.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
        clientDetails.setRegisteredRedirectUri(Collections.singleton("http://redirect.uri/*"));
        clientDetails.addAdditionalInformation(EmailAccountCreationService.SIGNUP_REDIRECT_URL, "http://redirect.uri/fallback");

        UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(), "clients.admin");
        return MockMvcUtils.createClient(getMockMvc(), adminToken, clientDetails);
    }

    private void createAccount(String expectedRedirectUri, String redirectUri) throws Exception {
        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        BaseClientDetails clientDetails = createTestClient();


        getMockMvc().perform(post("/create_account.do")
                                 .with(cookieCsrf())
                .param("email", userEmail)
                .param("password", USER_PASSWORD)
                .param("password_confirmation", USER_PASSWORD)
                .param("client_id", clientDetails.getClientId())
                .param("redirect_uri", redirectUri))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        Iterator receivedEmail = mailServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        assertTrue(message.getBody().contains("Cloud Foundry"));
        assertTrue(message.getHeaderValue("From").contains("Cloud Foundry"));

        getMockMvc().perform(get("/verify_user")
                .param("code", "test" + generator.counter.get()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT + "&form_redirect_uri=" + expectedRedirectUri))
                .andReturn();

        MvcResult mvcResult = loginWithAccount("")
            .andExpect(authenticated())
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail(), equalTo(userEmail));
        assertThat(principal.getOrigin(), equalTo(OriginKeys.UAA));
    }

    private ResultActions loginWithAccount(String subdomain) throws Exception {

        MockHttpServletRequestBuilder req = post("/login.do")
            .param("username", userEmail)
            .param("password", USER_PASSWORD)
            .with(cookieCsrf());

        if(hasText(subdomain)){
            req.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        }

        return getMockMvc().perform(req)
            .andExpect(status().isFound());
    }
}
