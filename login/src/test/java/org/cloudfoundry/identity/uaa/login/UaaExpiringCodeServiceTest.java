package org.cloudfoundry.identity.uaa.login;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

public class UaaExpiringCodeServiceTest {

    private RestTemplate uaaTemplate;
    private UaaExpiringCodeService service;
    private MockRestServiceServer mockUaaServer;

    @Before
    public void setUp() throws Exception {
        uaaTemplate = new RestTemplate();
        mockUaaServer = MockRestServiceServer.createServer(uaaTemplate);
        service = new UaaExpiringCodeService(uaaTemplate, "http://uaa.example.com");
    }

    @Test
    public void testGenerateCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis());

        String uaaResponseJson = "{" +
            "    \"code\":\"the_secret_code\"," +
            "    \"expiresAt\":" + ts.getTime() + "," +
            "    \"data\":\"{\\\"user_id\\\":\\\"user-id-001\\\",\\\"client_id\\\":\\\"login\\\"}\"" +
            "}";

        Map<String,String> data = new HashMap<>();
        data.put("user_id", "user-id-001");
        data.put("client_id", "login");

        mockUaaServer.expect(requestTo("http://uaa.example.com/Codes"))
            .andExpect(method(POST))
            .andExpect(jsonPath("$.data").value("{\"user_id\":\"user-id-001\",\"client_id\":\"login\"}"))
            .andExpect(jsonPath("$.expiresAt").exists())
            .andRespond(withSuccess(uaaResponseJson, APPLICATION_JSON));

        String code = service.generateCode(data, 1, TimeUnit.DAYS);
        assertEquals("the_secret_code", code);
    }

    @Test
    public void testVerifyCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis());
        String uaaResponseJson = "{" +
            "    \"code\":\"valid-code\"," +
            "    \"expiresAt\":" + ts.getTime() + "," +
            "    \"data\":\"{\\\"user_id\\\":\\\"user-id-001\\\",\\\"client_id\\\":\\\"login\\\"}\"" +
            "}";

        mockUaaServer.expect(requestTo("http://uaa.example.com/Codes/valid-code"))
            .andExpect(method(GET))
            .andRespond(withSuccess(uaaResponseJson, APPLICATION_JSON));
        Map<String,String> codeData = service.verifyCode("valid-code");
        mockUaaServer.verify();
        assertEquals("user-id-001", codeData.get("user_id"));
        assertEquals("login", codeData.get("client_id"));
    }

    @Test(expected = ExpiringCodeService.CodeNotFoundException.class)
    public void testVerifyCodeWithExpiredCode() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/Codes/invalid-code"))
            .andExpect(method(GET))
            .andRespond(withStatus(HttpStatus.NOT_FOUND));
        service.verifyCode("invalid-code");
    }

    @Test
    public void testVerifyCodeWithDataClass() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis());
        String uaaResponseJson = "{" +
            "    \"code\":\"valid-code\"," +
            "    \"expiresAt\":" + ts.getTime() + "," +
            "    \"data\":\"{\\\"user_id\\\":\\\"user-id-001\\\",\\\"client_id\\\":\\\"login\\\"}\"" +
            "}";

        mockUaaServer.expect(requestTo("http://uaa.example.com/Codes/valid-code"))
            .andExpect(method(GET))
            .andRespond(withSuccess(uaaResponseJson, APPLICATION_JSON));

        CodeResult codeResult = service.verifyCode(CodeResult.class, "valid-code");
        mockUaaServer.verify();

        assertEquals("user-id-001", codeResult.user_id);
        assertEquals("login", codeResult.client_id);
    }

    @Test(expected = ExpiringCodeService.CodeNotFoundException.class)
    public void testVerifyCodeWithDataClassWithExpiredCode() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/Codes/invalid-code"))
            .andExpect(method(GET))
            .andRespond(withStatus(HttpStatus.NOT_FOUND));
        service.verifyCode(CodeResult.class, "invalid-code");
    }

    public static class CodeResult {
        public String user_id;
        public String client_id;
    }
}