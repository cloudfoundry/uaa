package org.cloudfoundry.identity.uaa.authentication.manager;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
@RunWith(Parameterized.class)
public class KeystoneAuthenticationManagerTest {

    private RestTemplate restTemplate;
    private String remoteUrl;
    private RestAuthenticationManager restAuthenticationManager;
    private UsernamePasswordAuthenticationToken input;
    private String username = "testUserName";
    private String password = "testpassword";
    private Map<String,Object> restResult;

    public KeystoneAuthenticationManagerTest(RestAuthenticationManager authzManager, String url) {
        this.restAuthenticationManager = authzManager;
        this.remoteUrl = url;
    }

    @Parameterized.Parameters
    public static Collection parameters() {
        return Arrays.asList(new Object[][]{
            {new KeystoneAuthenticationManager(), "http://this.is.not.used/v3"},
            {new KeystoneAuthenticationManager(), "http://this.is.not.used/v2.0"},
            {new RestAuthenticationManager(), "http://this.is.not.used/authenticate"},
        });
    }

    @Before
    public void setUp() {
        input = new UsernamePasswordAuthenticationToken(username,password);
        setUpRestAuthenticationManager();
    }

    private void setUpRestAuthenticationManager() {
        setUpRestAuthenticationManager(HttpStatus.OK);
    }
    private void setUpRestAuthenticationManager(HttpStatus status ) {
        restResult = new HashMap<>();
        if (remoteUrl.contains("/v3")) {
            Map<String,Object> token = new HashMap<>();
            Map<String,Object> user = new HashMap<>();
            restResult.put("token", token);
            token.put("user", user);
            user.put("name", username);
        } else if (remoteUrl.contains("/v2.0")) {
            Map<String,Object> user = new HashMap<>();
            Map<String,Object> access = new HashMap<>();
            user.put("username", username);
            access.put("user", user);
            restResult.put("access", access);
        } else {
            restResult.put("username", username);
        }

        restTemplate = mock(RestTemplate.class);
        when(restTemplate.exchange(
            eq(remoteUrl),
            eq(HttpMethod.POST),
            any(HttpEntity.class),
            eq(Map.class)))
            .thenReturn(new ResponseEntity<Map>(restResult, status));


        restAuthenticationManager.setNullPassword(false);
        restAuthenticationManager.setRemoteUrl(remoteUrl);
        restAuthenticationManager.setRestTemplate(restTemplate);
    }

    @Test
    public void testV3Authentication() {
        restAuthenticationManager.authenticate(input);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testUnknownVersion() {
        Assume.assumeTrue(restAuthenticationManager instanceof KeystoneAuthenticationManager);
        remoteUrl = "http://this.is.not.used/v4";
        setUpRestAuthenticationManager();
        restAuthenticationManager.authenticate(input);
    }

    @Test(expected = BadCredentialsException.class)
    public void testUnauthorized() {
        setUpRestAuthenticationManager(HttpStatus.UNAUTHORIZED);
        restAuthenticationManager.authenticate(input);
    }

    @Test(expected = RuntimeException.class)
    public void test500Error() {
        setUpRestAuthenticationManager(HttpStatus.INTERNAL_SERVER_ERROR);
        restAuthenticationManager.authenticate(input);
    }

    @Test(expected = RuntimeException.class)
    public void testUnknownError() {
        setUpRestAuthenticationManager(HttpStatus.BAD_GATEWAY);
        restAuthenticationManager.authenticate(input);
    }

    @Test
    public void checkNullPassword() {
        assertFalse(restAuthenticationManager.isNullPassword());
    }

}