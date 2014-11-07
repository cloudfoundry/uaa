package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring4.SpringTemplateEngine;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.contains;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isNull;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = ThymeleafConfig.class)
public class EmailChangeEmailServiceTest {
    private EmailChangeEmailService emailChangeEmailService;
    private MockRestServiceServer mockUaaServer;
    private MessageService messageService;

    @Autowired
    @Qualifier("mailTemplateEngine")
    SpringTemplateEngine templateEngine;
    private RestTemplate uaaTemplate;

    @Before
    public void setUp() throws Exception {
        uaaTemplate = new RestTemplate();
        mockUaaServer = MockRestServiceServer.createServer(uaaTemplate);
        messageService = Mockito.mock(EmailService.class);
        emailChangeEmailService = new EmailChangeEmailService(templateEngine, messageService, uaaTemplate, "http://uaa.example.com/uaa", "pivotal");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }


    @Test
    public void beginEmailChange() throws Exception {
        setUpForSuccess();

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app");

        mockUaaServer.verify();

        Mockito.verify(messageService).sendMessage((String) isNull(),
            eq("new@example.com"),
            eq(MessageType.CHANGE_EMAIL),
            eq("Email change verification"),
            contains("<a href=\"http://localhost/login/verify_email?code=the_secret_code\">Verify your email</a>")
        );
    }

    @Test
    public void testBeginEmailChangeWithOssBrand() throws Exception {
        emailChangeEmailService = new EmailChangeEmailService(templateEngine, messageService, uaaTemplate, "http://uaa.example.com/uaa", "oss");

        setUpForSuccess();

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app");

        mockUaaServer.verify();

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage((String) isNull(),
            eq("new@example.com"),
            eq(MessageType.CHANGE_EMAIL),
            eq("Email change verification"),
            emailBodyArgument.capture()
        );

        String emailBody = emailBodyArgument.getValue();

        assertThat(emailBody, containsString("<a href=\"http://localhost/login/verify_email?code=the_secret_code\">Verify your email</a>"));
        assertThat(emailBody, containsString("an account"));
        assertThat(emailBody, containsString("Cloud Foundry"));
        assertThat(emailBody, not(containsString("a Pivotal ID")));
    }

    @Test(expected = UaaException.class)
    public void beginEmailChangeWithUsernameConflict() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/uaa/email_verifications"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.userId").value("user-001"))
            .andExpect(jsonPath("$.email").value("new@example.com"))
            .andRespond(withStatus(HttpStatus.CONFLICT));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", null);
    }

    @Test
    public void testCompleteVerification() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/uaa/email_changes"))
            .andExpect(method(POST))
            .andExpect(content().string("the_secret_code"))
            .andRespond(withSuccess("{" +
                "  \"user_id\":\"user-001\"," +
                "  \"username\":\"new@example.com\"," +
                "  \"email\": \"new@example.com\" " +
                "}", APPLICATION_JSON));

        emailChangeEmailService.completeVerification("the_secret_code");

        mockUaaServer.verify();
    }

    @Test(expected = UaaException.class)
    public void testCompleteVerificationWithInvalidCode() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/uaa/email_changes"))
            .andExpect(method(POST))
            .andExpect(content().string("the_secret_code"))
            .andRespond(withBadRequest());

        emailChangeEmailService.completeVerification("the_secret_code");

        mockUaaServer.verify();
    }

    private void setUpForSuccess() {
        mockUaaServer.expect(requestTo("http://uaa.example.com/uaa/email_verifications"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.userId").value("user-001"))
            .andExpect(jsonPath("$.email").value("new@example.com"))
            .andExpect(jsonPath("$.client_id").value("app"))
            .andRespond(withSuccess("the_secret_code", APPLICATION_JSON));
    }
}