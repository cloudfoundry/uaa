package org.cloudfoundry.identity.uaa.authentication.manager;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class KeystoneAuthenticationManagerTest {

    private RestTemplate restTemplate;
    private String remoteUrl;
    private RestAuthenticationManager restAuthenticationManager;
    private UsernamePasswordAuthenticationToken input;
    private String username = "testUserName";
    private String password = "testpassword";
    private Map<String,Object> restResult;

    @Before
    public void setUp() throws Exception {
        remoteUrl = "http://this.is.not.used/v3";
        input = new UsernamePasswordAuthenticationToken(username,password);
        restAuthenticationManager = new KeystoneAuthenticationManager();
        setUpRestAuthenticationManager();
    }

    private void setUpRestAuthenticationManager() {
        restResult = new HashMap<>();
        if (remoteUrl.indexOf("/v3")>=0) {
            Map<String,Object> token = new HashMap<>();
            Map<String,Object> user = new HashMap<>();
            restResult.put("token", token);
            token.put("user", user);
            user.put("name", username);
        } else {
            Map<String,Object> user = new HashMap<>();
            Map<String,Object> access = new HashMap<>();
            user.put("username", username);
            access.put("user", user);
            restResult.put("access", access);
        }

        restTemplate = mock(RestTemplate.class);
        when(restTemplate.exchange(
            eq(remoteUrl),
            eq(HttpMethod.POST),
            any(HttpEntity.class),
            eq(Map.class)))
            .thenReturn(new ResponseEntity<Map>(restResult, HttpStatus.OK));


        restAuthenticationManager.setNullPassword(false);
        restAuthenticationManager.setRemoteUrl(remoteUrl);
        restAuthenticationManager.setRestTemplate(restTemplate);
    }

    @Test
    public void testV3Authentication() throws Exception {
        restAuthenticationManager.authenticate(input);
    }

    @Test
    public void testV2Authentication() throws Exception {
        remoteUrl = "http://this.is.not.used/v2.0";
        setUpRestAuthenticationManager();
        restAuthenticationManager.authenticate(input);
    }

}