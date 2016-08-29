/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.app.integration;

import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;

/**
 * Tests implicit grant using a direct posting of credentials to the /authorize
 * endpoint and also with an intermediate
 * form login.
 *
 * @author Dave Syer
 */
public class AuthenticationIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Test
    public void formLoginSucceeds() throws Exception {

        ResponseEntity<String> result;
        String location;

        HttpHeaders uaaHeaders = new HttpHeaders();
        HttpHeaders appHeaders = new HttpHeaders();
        uaaHeaders.setAccept(Arrays.asList(MediaType.TEXT_HTML));
        appHeaders.setAccept(Arrays.asList(MediaType.TEXT_HTML));

        // *** GET /app/id
        result = serverRunning.getForString("/id", appHeaders);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        location = result.getHeaders().getLocation().toString();

        for (String cookie : result.getHeaders().get("Set-Cookie")) {
            assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
            appHeaders.add("Cookie", cookie);
        }

        assertTrue("Wrong location: " + location, location.contains("/oauth/authorize"));
        // *** GET /uaa/oauth/authorize
        result = serverRunning.getForString(location, uaaHeaders);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        location = result.getHeaders().getLocation().toString();

        for (String cookie : result.getHeaders().get("Set-Cookie")) {
            assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
            uaaHeaders.add("Cookie", cookie);
        }

        assertTrue("Wrong location: " + location, location.contains("/login"));

        result = serverRunning.getForString(location, uaaHeaders);
        if (result.getHeaders().get("Set-Cookie") != null) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
                uaaHeaders.add("Cookie", cookie);
            }
        }

        location = serverRunning.getAuthServerUrl("/login.do");

        MultiValueMap<String, String> formData;
        formData = new LinkedMultiValueMap<>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());
        formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, extractCookieCsrf(result.getBody()));

        // *** POST /uaa/login.do
        result = serverRunning.postForString(location, formData, uaaHeaders);

        for (String cookie : result.getHeaders().get("Set-Cookie")) {
            assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
            uaaHeaders.add("Cookie", cookie);
        }

        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        location = result.getHeaders().getLocation().toString();

        assertTrue("Wrong location: " + location, location.contains("/oauth/authorize"));
        // *** GET /uaa/oauth/authorize
        result = serverRunning.getForString(location, uaaHeaders);

        // If there is no token in place already for this client we get the
        // approval page.
        // TODO: revoke the token so we always get the approval page
        if (result.getStatusCode() == HttpStatus.OK) {
            location = serverRunning.getAuthServerUrl("/oauth/authorize");

            formData = new LinkedMultiValueMap<String, String>();
            formData.add(USER_OAUTH_APPROVAL, "true");

            // *** POST /uaa/oauth/authorize
            result = serverRunning.postForString(location, formData, uaaHeaders);
        }

        location = result.getHeaders().getLocation().toString();

        // SUCCESS
        assertTrue("Wrong location: " + location, location.contains("/id"));

        // *** GET /app/id
        result = serverRunning.getForString(location, appHeaders);
        // System.err.println(result.getHeaders());
        assertEquals(HttpStatus.OK, result.getStatusCode());
    }

    public static String extractCookieCsrf(String body) {
        String pattern = "\\<input type=\\\"hidden\\\" name=\\\"X-Uaa-Csrf\\\" value=\\\"(.*?)\\\"";

        Pattern linkPattern = Pattern.compile(pattern);
        Matcher matcher = linkPattern.matcher(body);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
}
