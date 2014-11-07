package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.codehaus.jackson.map.ObjectMapper;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.ResponseCreator;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = ThymeleafConfig.class)
public class EmailAccountCreationServiceTests {

    private EmailAccountCreationService emailAccountCreationService;
    private MockRestServiceServer mockUaaServer;
    private MessageService messageService;
    private RestTemplate uaaTemplate;

    @Autowired
    @Qualifier("mailTemplateEngine")
    SpringTemplateEngine templateEngine;

    @Before
    public void setUp() throws Exception {
        uaaTemplate = new RestTemplate();
        mockUaaServer = MockRestServiceServer.createServer(uaaTemplate);
        messageService = mock(MessageService.class);
        emailAccountCreationService = new EmailAccountCreationService(new ObjectMapper(), templateEngine, messageService, uaaTemplate, "http://uaa.example.com", "pivotal", "http://login.example.com");
    }

    @Test
    public void testBeginActivation() throws Exception {
        setUpForSuccess();

        emailAccountCreationService.beginActivation("user@example.com", "password", "login");

        mockUaaServer.verify();

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        verify(messageService).sendMessage(
            eq("newly-created-user-id"),
            eq("user@example.com"),
            eq(MessageType.CREATE_ACCOUNT_CONFIRMATION),
            eq("Activate your Pivotal ID"),
            emailBodyArgument.capture()
        );
        String emailBody = emailBodyArgument.getValue();
        assertThat(emailBody, containsString("a Pivotal ID"));
        assertThat(emailBody, containsString("<a href=\"http://login.example.com/verify_user?code=the_secret_code&amp;email=user%40example.com\">Activate your account</a>"));
        assertThat(emailBody, not(containsString("Cloud Foundry")));
    }

    @Test
    public void testBeginActivationWithOssBrand() throws Exception {
        emailAccountCreationService = new EmailAccountCreationService(new ObjectMapper(), templateEngine, messageService, uaaTemplate, "http://uaa.example.com", "oss", "http://login.example.com");

        setUpForSuccess();

        emailAccountCreationService.beginActivation("user@example.com", "password", "login");

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        verify(messageService).sendMessage(
            eq("newly-created-user-id"),
            eq("user@example.com"),
            eq(MessageType.CREATE_ACCOUNT_CONFIRMATION),
            eq("Activate your account"),
            emailBodyArgument.capture()
        );
        String emailBody = emailBodyArgument.getValue();
        assertThat(emailBody, containsString("an account"));
        assertThat(emailBody, containsString("<a href=\"http://login.example.com/verify_user?code=the_secret_code&amp;email=user%40example.com\">Activate your account</a>"));
        assertThat(emailBody, not(containsString("Pivotal")));
    }

    @Test(expected = UaaException.class)
    public void testBeginActivationWithExistingUser() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/Users"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.userName").value("user@example.com"))
            .andExpect(jsonPath("$.password").value("password"))
            .andExpect(jsonPath("$.origin").value("uaa"))
            .andExpect(jsonPath("$.emails[0].value").value("user@example.com"))
            .andRespond(new ResponseCreator() {
                @Override
                public ClientHttpResponse createResponse(ClientHttpRequest request) throws IOException {
                    return new MockClientHttpResponse("{\"error\":\"invalid_user\",\"message\":\"error message\",\"user_id\":\"existing-user-id\",\"verified\":true,\"active\":true}".getBytes(), CONFLICT);
                }
            });
        emailAccountCreationService.beginActivation("user@example.com", "password", "login");
    }

    @Test
    public void testBeginActivationWithUnverifiedExistingUser() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/Users"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.userName").value("user@example.com"))
            .andExpect(jsonPath("$.password").value("password"))
            .andExpect(jsonPath("$.origin").value("uaa"))
            .andExpect(jsonPath("$.emails[0].value").value("user@example.com"))
            .andRespond(new ResponseCreator() {
                @Override
                public ClientHttpResponse createResponse(ClientHttpRequest request) throws IOException {
                    return new MockClientHttpResponse("{\"error\":\"invalid_user\",\"message\":\"error message\",\"user_id\":\"existing-user-id\",\"verified\":false,\"active\":true}".getBytes(), CONFLICT);
                }
            });

        String uaaResponseJson = "{" +
            "    \"code\":\"the_secret_code\"," +
            "    \"expiresAt\":9999999999," +
            "    \"data\":\"{\\\"user_id\\\":\\\"existing-user-id\\\",\\\"client_id\\\":\\\"login\\\"}\"" +
            "}";

        mockUaaServer.expect(requestTo("http://uaa.example.com/Codes"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.data").value("{\"user_id\":\"existing-user-id\",\"client_id\":\"login\"}"))
            .andRespond(withSuccess(uaaResponseJson, APPLICATION_JSON));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        emailAccountCreationService.beginActivation("user@example.com", "password", "login");

        verify(messageService).sendMessage(
            eq("existing-user-id"),
            eq("user@example.com"),
            eq(MessageType.CREATE_ACCOUNT_CONFIRMATION),
            anyString(),
            anyString()
        );
    }

    @Test
    public void testCompleteActivation() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + (60 * 60 * 1000)); // 1 hour
        String uaaResponseJson = "{" +
            "    \"code\":\"the_secret_code\"," +
            "    \"expiresAt\":" + ts.getTime() + "," +
            "    \"data\":\"{\\\"user_id\\\":\\\"newly-created-user-id\\\",\\\"client_id\\\":\\\"app\\\"}\"" +
            "}";

        mockUaaServer.expect(requestTo("http://uaa.example.com/Codes/the_secret_code"))
            .andExpect(method(GET))
            .andRespond(withSuccess(uaaResponseJson, APPLICATION_JSON));

        String scimUserJSONString = "{" +
            "\"userName\": \"user@example.com\"," +
            "\"id\": \"newly-created-user-id\"," +
            "\"emails\": [{\"value\":\"user@example.com\"}]" +
            "}";

        mockUaaServer.expect(requestTo("http://uaa.example.com/Users/newly-created-user-id/verify"))
            .andExpect(method(GET))
            .andRespond(withSuccess(scimUserJSONString, APPLICATION_JSON));

        Map<String,Object> additionalInformation = new HashMap<>();
        additionalInformation.put("signup_redirect_url", "http://example.com/redirect");

        String clientDetails = "{" +
                "\"client_id\": \"app\"," +
                "\"signup_redirect_url\": \"http://example.com/redirect\"" +
            "}";

        mockUaaServer.expect(requestTo("http://uaa.example.com/oauth/clients/app"))
            .andExpect(method(GET))
            .andRespond(withSuccess(clientDetails, APPLICATION_JSON));

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");

        mockUaaServer.verify();

        assertEquals("user@example.com", accountCreation.getUsername());
        assertEquals("newly-created-user-id", accountCreation.getUserId());
        assertEquals("http://example.com/redirect", accountCreation.getRedirectLocation());
        assertNotNull(accountCreation.getUserId());
    }

    @Test
    public void testCompleteActivationWithExpiredCode() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/Codes/expiring_code"))
            .andExpect(method(GET))
            .andRespond(withStatus(BAD_REQUEST));

        try {
            emailAccountCreationService.completeActivation("expiring_code");
            fail();
        } catch(HttpClientErrorException e) {
            assertThat(e.getStatusCode(), Matchers.equalTo(BAD_REQUEST));
        }
    }

    @Test
    public void testResendVerificationCode() throws Exception {
        String uaaResponse = "{\n" +
            "  \"resources\": [\n" +
            "    {\n" +
            "      \"id\": \"unverified-user-id\",\n" +
            "      \"userName\": \"user@example.com\",\n" +
            "      \"origin\": \"uaa\"\n" +
            "    }\n" +
            "  ],\n" +
            "  \"startIndex\": 1,\n" +
            "  \"itemsPerPage\": 100,\n" +
            "  \"totalResults\": 1,\n" +
            "  \"schemas\": [\n" +
            "    \"urn:scim:schemas:core:1.0\"\n" +
            "  ]\n" +
            "}";
        mockUaaServer.expect(requestTo("http://uaa.example.com/ids/Users?attributes=id&filter=userName%20eq%20%22user@example.com%22%20and%20origin%20eq%20%22uaa%22"))
            .andExpect(method(GET))
            .andRespond(withSuccess(uaaResponse, APPLICATION_JSON));

        Timestamp ts = new Timestamp(System.currentTimeMillis() + (60 * 60 * 1000)); // 1 hour
        String uaaResponseJson = "{" +
            "    \"code\":\"the_secret_code\"," +
            "    \"expiresAt\":" + ts.getTime() + "," +
            "    \"data\":\"{\\\"user_id\\\":\\\"unverified-user-id\\\",\\\"client_id\\\":\\\"login\\\"}\"" +
            "}";
        mockUaaServer.expect(requestTo("http://uaa.example.com/Codes"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.expiresAt").value(Matchers.greaterThan(ts.getTime() - 5000)))
            .andExpect(jsonPath("$.expiresAt").value(Matchers.lessThan(ts.getTime() + 5000)))
            .andExpect(jsonPath("$.data").exists()) // we can't tell what order the json keys will take in the serialized json, so exists is the best we can do
            .andRespond(withSuccess(uaaResponseJson, APPLICATION_JSON));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        emailAccountCreationService.resendVerificationCode("user@example.com", "login");

        mockUaaServer.verify();

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        verify(messageService).sendMessage(eq("unverified-user-id"),
            eq("user@example.com"),
            eq(MessageType.CREATE_ACCOUNT_CONFIRMATION),
            eq("Activate your Pivotal ID"),
            emailBodyArgument.capture()
        );
        String emailBody = emailBodyArgument.getValue();
        assertThat(emailBody, containsString("a Pivotal ID"));
        assertThat(emailBody, containsString("<a href=\"http://login.example.com/verify_user?code=the_secret_code&amp;email=user%40example.com\">Activate your account</a>"));
        assertThat(emailBody, not(containsString("Cloud Foundry")));
    }

    private void setUpForSuccess() {
        String scimUserJSONString = "{" +
            "\"userName\": \"user@example.com\"," +
            "\"id\": \"newly-created-user-id\"," +
            "\"emails\": [{\"value\":\"user@example.com\"}]" +
            "}";
        mockUaaServer.expect(requestTo("http://uaa.example.com/Users"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.userName").value("user@example.com"))
            .andExpect(jsonPath("$.password").value("password"))
            .andExpect(jsonPath("$.origin").value("uaa"))
            .andExpect(jsonPath("$.active").value(true))
            .andExpect(jsonPath("$.verified").value(false))
            .andExpect(jsonPath("$.emails[0].value").value("user@example.com"))
            .andRespond(withSuccess(scimUserJSONString, APPLICATION_JSON));

        Timestamp ts = new Timestamp(System.currentTimeMillis() + (60 * 60 * 1000)); // 1 hour
        String uaaResponseJson = "{" +
            "    \"code\":\"the_secret_code\"," +
            "    \"expiresAt\":" + ts.getTime() + "," +
            "    \"data\":\"{\\\"user_id\\\":\\\"newly-created-user-id\\\",\\\"client_id\\\":\\\"login\\\"}\"" +
            "}";
        mockUaaServer.expect(requestTo("http://uaa.example.com/Codes"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.expiresAt").value(Matchers.greaterThan(ts.getTime() - 5000)))
            .andExpect(jsonPath("$.expiresAt").value(Matchers.lessThan(ts.getTime() + 5000)))
            .andExpect(jsonPath("$.data").exists()) // we can't tell what order the json keys will take in the serialized json, so exists is the best we can do
            .andRespond(withSuccess(uaaResponseJson, APPLICATION_JSON));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }
}