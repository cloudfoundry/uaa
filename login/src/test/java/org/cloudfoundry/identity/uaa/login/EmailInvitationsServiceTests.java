package org.cloudfoundry.identity.uaa.login;

import java.nio.charset.Charset;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.sun.corba.se.impl.orb.ORBConfiguratorImpl;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.oauth.ClientAdminEndpoints;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.thymeleaf.spring4.SpringTemplateEngine;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = EmailInvitationsServiceTests.ContextConfiguration.class)
@DirtiesContext(classMode=ClassMode.AFTER_EACH_TEST_METHOD)
public class EmailInvitationsServiceTests {

    @Autowired
    ConfigurableWebApplicationContext webApplicationContext;

    @Autowired
    ExpiringCodeService expiringCodeService;

    @Autowired
    EmailInvitationsService emailInvitationsService;

    @Autowired
    AccountCreationService accountCreationService;

    @Autowired
    MessageService messageService;

    @Autowired
    ScimUserProvisioning scimUserProvisioning;

    @Autowired
    ClientAdminEndpoints clientAdminEndpoints;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .build();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testSendInviteEmail() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ArgumentCaptor<Map<String,String>> captor = ArgumentCaptor.forClass((Class)Map.class);

        when(expiringCodeService.generateCode(captor.capture(), anyInt(), eq(TimeUnit.DAYS))).thenReturn("the_secret_code");
        emailInvitationsService.inviteUser("user@example.com", "current-user");

        Map<String,String> data = captor.getValue();
        assertEquals("existing-user-id", data.get("user_id"));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage(
            eq("existing-user-id"),
            eq("user@example.com"),
            eq(MessageType.INVITATION),
            eq("Invitation to join Pivotal"),
            emailBodyArgument.capture()
        );
        String emailBody = emailBodyArgument.getValue();
        assertThat(emailBody, containsString("current-user"));
        assertThat(emailBody, containsString("Pivotal"));
        assertThat(emailBody, containsString("<a href=\"http://localhost/login/invitations/accept?code=the_secret_code\">Accept Invite</a>"));
        assertThat(emailBody, not(containsString("Cloud Foundry")));
    }
    
    @Test(expected = UaaException.class)
    public void testSendInviteEmailToUserThatIsAlreadyVerified() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");


        emailInvitationsService.inviteUser("alreadyverified@example.com", "current-user");
    }
    
    @Test
    public void testSendInviteEmailToUnverifiedUser() throws Exception {
    	
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setProtocol("http");
		request.setContextPath("/login");
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
		
		byte[] errorResponse = "{\"error\":\"invalid_user\",\"message\":\"error message\",\"user_id\":\"existing-user-id\",\"verified\":false,\"active\":true}".getBytes();
		when(accountCreationService.createUser("user@example.com", null)).thenThrow(new HttpClientErrorException(HttpStatus.CONFLICT,"invalid user",errorResponse,Charset.forName("UTF-8")));

        ArgumentCaptor<Map<String,String>> captor = ArgumentCaptor.forClass((Class)Map.class);

        when(expiringCodeService.generateCode(captor.capture(), anyInt(), eq(TimeUnit.DAYS))).thenReturn("the_secret_code");
        emailInvitationsService.inviteUser("user@example.com", "current-user");

        Map<String,String> data = captor.getValue();
        assertEquals("existing-user-id", data.get("user_id"));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage(
            eq("existing-user-id"),
            eq("user@example.com"),
            eq(MessageType.INVITATION),
            eq("Invitation to join Pivotal"),
            emailBodyArgument.capture()
        );
        String emailBody = emailBodyArgument.getValue();
        assertThat(emailBody, containsString("current-user"));
        assertThat(emailBody, containsString("Pivotal"));
        assertThat(emailBody, containsString("<a href=\"http://localhost/login/invitations/accept?code=the_secret_code\">Accept Invite</a>"));
        assertThat(emailBody, not(containsString("Cloud Foundry")));
    }

    @Test
    public void testSendInviteEmailWithOSSBrand() throws Exception {
        emailInvitationsService.setBrand("oss");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ArgumentCaptor<Map<String,String>> captor = ArgumentCaptor.forClass((Class)Map.class);

        when(expiringCodeService.generateCode(captor.capture(), anyInt(), eq(TimeUnit.DAYS))).thenReturn("the_secret_code");
        emailInvitationsService.inviteUser("user@example.com", "current-user");

        Map<String,String> data = captor.getValue();
        assertEquals("existing-user-id", data.get("user_id"));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage(
            eq("existing-user-id"),
            eq("user@example.com"),
            eq(MessageType.INVITATION),
            eq("Invitation to join Cloud Foundry"),
            emailBodyArgument.capture()
        );
        String emailBody = emailBodyArgument.getValue();
        assertThat(emailBody, containsString("current-user"));
        assertThat(emailBody, containsString("<a href=\"http://localhost/login/invitations/accept?code=the_secret_code\">Accept Invite</a>"));
        assertThat(emailBody, containsString("Cloud Foundry"));
        assertThat(emailBody, not(containsString("Pivotal")));
    }

    @Test
    public void testAcceptInvitation() throws Exception {


        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        BaseClientDetails clientDetails = new BaseClientDetails("app", null, null, null, null, "http://example.com/redirect");
        clientDetails.addAdditionalInformation("invitation_redirect_url", "http://example.com/redirect");
        when(scimUserProvisioning.retrieve(eq("user-id-001"))).thenReturn(user);
        when(clientAdminEndpoints.getClientDetails(eq("app"))).thenReturn(clientDetails);
        String redirectLocation = emailInvitationsService.acceptInvitation("user-id-001", "user@example.com", "secret", "app");

        Mockito.verifyZeroInteractions(expiringCodeService);
        assertEquals("http://example.com/redirect", redirectLocation);
    }

    @Test
    public void testAcceptInvitationWithNoClientRedirect() throws Exception {

        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        when(scimUserProvisioning.retrieve(eq("user-id-001"))).thenReturn(user);

        String redirectLocation = emailInvitationsService.acceptInvitation("user-id-001", "user@example.com", "secret", "");
        Mockito.verifyZeroInteractions(expiringCodeService);
        assertNull(redirectLocation);
    }

    @Configuration
    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration extends WebMvcConfigurerAdapter {

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Autowired
        @Qualifier("mailTemplateEngine")
        SpringTemplateEngine templateEngine;

        @Bean
        ExpiringCodeService expiringCodeService() { return mock(ExpiringCodeService.class); }

        @Bean
        MessageService messageService() {
            return mock(MessageService.class);
        }

        @Bean
        AccountCreationService accountCreationService() {
            AccountCreationService svc =  mock(AccountCreationService.class);
            when(svc.createUser(anyString(), anyString())).thenAnswer(createUserArgs());
            return svc;
        }

        @Bean
        EmailInvitationsService emailInvitationsService() {
            return new EmailInvitationsService(templateEngine, messageService(), "pivotal");
        }

        @Bean
        ClientAdminEndpoints clientAdminEndpoints() {
            return mock(ClientAdminEndpoints.class);
        }

        @Bean
        ScimUserProvisioning scimUserProvisioning() {
            return mock(ScimUserProvisioning.class);
        }

    }
    private static Answer<ScimUser> createUserArgs() {
        return new Answer<ScimUser>() {
            @Override
            public ScimUser answer(InvocationOnMock invocation) throws Throwable {
                String email = invocation.getArguments()[0].toString();
                ScimUser user = new ScimUser("existing-user-id", email, "fname", "lname");
                user.setOrigin(Origin.UAA);
                user.setPrimaryEmail(user.getUserName());
                if (email.contains("alreadyverified")) {
                    throw new UaaException("exists");
                }
                return user;
            }
        };
    }
}
