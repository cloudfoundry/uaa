package org.cloudfoundry.identity.uaa.login;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.contains;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.scim.endpoints.ChangeEmailEndpoints;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring4.SpringTemplateEngine;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = ThymeleafConfig.class)
public class EmailChangeEmailServiceTest {
    private EmailChangeEmailService emailChangeEmailService;
    private ChangeEmailEndpoints endpoints;
    private MessageService messageService;

    @Autowired
    @Qualifier("mailTemplateEngine")
    SpringTemplateEngine templateEngine;

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        endpoints = mock(ChangeEmailEndpoints.class);
        messageService = mock(EmailService.class);
        emailChangeEmailService = new EmailChangeEmailService(templateEngine, messageService, "pivotal", endpoints);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }


    @Test
    public void beginEmailChange() throws Exception {
        when(endpoints.generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class))).thenReturn(new ResponseEntity<>("the_secret_code", HttpStatus.CREATED));
        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app");

        verify(endpoints).generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class));

        Mockito.verify(messageService).sendMessage((String) isNull(),
            eq("new@example.com"),
            eq(MessageType.CHANGE_EMAIL),
            eq("Email change verification"),
            contains("<a href=\"http://localhost/login/verify_email?code=the_secret_code\">Verify your email</a>")
        );
    }

    @Test
    public void testBeginEmailChangeWithOssBrand() throws Exception {
        emailChangeEmailService = new EmailChangeEmailService(templateEngine, messageService, "oss", endpoints);

        when(endpoints.generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class))).thenReturn(new ResponseEntity<>("the_secret_code", HttpStatus.CREATED));
        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app");

        verify(endpoints).generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class));

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
        ResponseEntity<String> responseEntity = new ResponseEntity<>(HttpStatus.CONFLICT);
        when(endpoints.generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class))).thenReturn(responseEntity);
        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", null);
    }

    @Test
    public void testCompleteVerification() throws Exception {
        ChangeEmailEndpoints.EmailChangeResponse response = new ChangeEmailEndpoints.EmailChangeResponse();
        response.setUserId("user_id");
        response.setEmail("email@email.com");
        response.setUserId("username");
        ResponseEntity<ChangeEmailEndpoints.EmailChangeResponse> responseEntity = new ResponseEntity<>(response, HttpStatus.OK);
        when(endpoints.changeEmail(eq("the_secret_code"))).thenReturn(responseEntity);
        emailChangeEmailService.completeVerification("the_secret_code");
        verify(endpoints).changeEmail(eq("the_secret_code"));

    }

    @Test(expected = UaaException.class)
    public void testCompleteVerificationWithInvalidCode() throws Exception {
        ChangeEmailEndpoints.EmailChangeResponse response = new ChangeEmailEndpoints.EmailChangeResponse();
        response.setUserId("user_id");
        response.setEmail("email@email.com");
        response.setUserId("username");
        ResponseEntity<ChangeEmailEndpoints.EmailChangeResponse> responseEntity = new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        when(endpoints.changeEmail(eq("the_secret_code"))).thenReturn(responseEntity);
        emailChangeEmailService.completeVerification("the_secret_code");
    }

}