package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
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

import java.nio.charset.Charset;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = EmailInvitationsServiceTests.ContextConfiguration.class)
@DirtiesContext(classMode=ClassMode.AFTER_EACH_TEST_METHOD)
public class EmailInvitationsServiceTests {

    private MockRestServiceServer mockUaaServer;

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
    RestTemplate authorizationTemplate;

    @Before
    public void setUp() throws Exception {
        mockUaaServer = MockRestServiceServer.createServer(authorizationTemplate);

        MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .build();
    }

    @Test
    public void testSendInviteEmail() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ScimUser user = new ScimUser();
        user.setId("user-id-001");

        when(accountCreationService.createUser("user@example.com", null)).thenReturn(user);

        ArgumentCaptor<Map<String,String>> captor = ArgumentCaptor.forClass((Class)Map.class);

        when(expiringCodeService.generateCode(captor.capture(), anyInt(), eq(TimeUnit.DAYS))).thenReturn("the_secret_code");
        emailInvitationsService.inviteUser("user@example.com", "current-user");

        Map<String,String> data = captor.getValue();
        assertEquals("user-id-001", data.get("user_id"));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage(
            eq("user-id-001"),
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

        byte[] errorResponse = "{\"error\":\"invalid_user\",\"message\":\"error message\",\"user_id\":\"existing-user-id\",\"verified\":true,\"active\":true}".getBytes();
        when(accountCreationService.createUser("user@example.com", null)).thenThrow(new HttpClientErrorException(HttpStatus.CONFLICT,"invalid user",errorResponse,Charset.forName("UTF-8")));

        emailInvitationsService.inviteUser("user@example.com", "current-user");
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

        ScimUser user = new ScimUser();
        user.setId("user-id-001");

        when(accountCreationService.createUser("user@example.com", null)).thenReturn(user);
        ArgumentCaptor<Map<String,String>> captor = ArgumentCaptor.forClass((Class)Map.class);

        when(expiringCodeService.generateCode(captor.capture(), anyInt(), eq(TimeUnit.DAYS))).thenReturn("the_secret_code");
        emailInvitationsService.inviteUser("user@example.com", "current-user");

        Map<String,String> data = captor.getValue();
        assertEquals("user-id-001", data.get("user_id"));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage(
            eq("user-id-001"),
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

        mockUaaServer.expect(requestTo("http://uaa.example.com/Users/user-id-001/verify"))
            .andExpect(method(GET))
            .andRespond(withSuccess("{}",APPLICATION_JSON));

        String clientDetails = "{" +
            "\"client_id\": \"app\"," +
            "\"invitation_redirect_url\": \"http://example.com/redirect\"" +
            "}";

        mockUaaServer.expect(requestTo("http://uaa.example.com/Users/user-id-001/password"))
            .andExpect(method(PUT))
            .andExpect(jsonPath("$.password").value("secret"))
            .andRespond(withSuccess());

        mockUaaServer.expect(requestTo("http://uaa.example.com/oauth/clients/app"))
            .andExpect(method(GET))
            .andRespond(withSuccess(clientDetails, APPLICATION_JSON));

        String redirectLocation = emailInvitationsService.acceptInvitation("user-id-001", "user@example.com", "secret", "app");

        mockUaaServer.verify();
        Mockito.verifyZeroInteractions(expiringCodeService);
        assertEquals("http://example.com/redirect", redirectLocation);
    }

    @Test
    public void testAcceptInvitationWithNoClientRedirect() throws Exception {

        mockUaaServer.expect(requestTo("http://uaa.example.com/Users/user-id-001/verify"))
            .andExpect(method(GET))
            .andRespond(withSuccess("{}",APPLICATION_JSON));

        mockUaaServer.expect(requestTo("http://uaa.example.com/Users/user-id-001/password"))
            .andExpect(method(PUT))
            .andExpect(jsonPath("$.password").value("secret"))
            .andRespond(withSuccess());

        String redirectLocation = emailInvitationsService.acceptInvitation("user-id-001", "user@example.com", "secret", "");

        mockUaaServer.verify();
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
        ExpiringCodeService expiringCodeService() { return Mockito.mock(ExpiringCodeService.class); }

        @Bean
        MessageService messageService() {
            return Mockito.mock(MessageService.class);
        }

        @Bean
        AccountCreationService accountCreationService() {
            return Mockito.mock(AccountCreationService.class);
        }

        @Bean
        EmailInvitationsService emailInvitationsService() {
            return new EmailInvitationsService(templateEngine, messageService(), "pivotal", "http://uaa.example.com");
        }

        @Bean
        RestTemplate authorizationTemplate() {
            return new RestTemplate();
        }

    }
}
