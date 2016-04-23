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
package org.cloudfoundry.identity.uaa.integration.feature;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.HtmlUtils;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TestClient {

    private final RestTemplate restTemplate;
    private final String baseUrl;
    private final String uaaUrl;

    public TestClient(RestTemplate restTemplate, String baseUrl, String uaaUrl ) {
        this.restTemplate = restTemplate;
        this.baseUrl = baseUrl;
        this.uaaUrl = uaaUrl;
    }

    public String getBasicAuthHeaderValue(String username, String password) {
        return "Basic " + new String(Base64.encodeBase64((username + ":" + password).getBytes()));
    }

    public String getOAuthAccessToken(String username, String password, String grantType, String scope) {
        return getOAuthAccessToken(baseUrl, username, password, grantType, scope);
    }
    public String getOAuthAccessToken(String baseUrl, String username, String password, String grantType, String scope) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", getBasicAuthHeaderValue(username, password));

        MultiValueMap<String, String> postParameters = new LinkedMultiValueMap<String, String>();
        postParameters.add("grant_type", grantType);
        postParameters.add("client_id", username);
        if(scope != null) { postParameters.add("scope", scope); }

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<MultiValueMap<String, String>>(postParameters, headers);

        ResponseEntity<Map> exchange = restTemplate.exchange(baseUrl + "/oauth/token", HttpMethod.POST, requestEntity, Map.class);

        return exchange.getBody().get("access_token").toString();
    }

    public void createClient(String adminAccessToken, BaseClientDetails clientDetails) throws Exception {
        restfulCreate(
            adminAccessToken,
            JsonUtils.writeValueAsString(clientDetails),
            uaaUrl + "/oauth/clients"
        );
    }

    public void createScimClient(String adminAccessToken, String clientId) throws Exception {
        restfulCreate(
                adminAccessToken,
                "{" +
                        "\"scope\":[\"uaa.none\"]," +
                        "\"client_id\":\"" + clientId + "\"," +
                        "\"client_secret\":\"scimsecret\"," +
                        "\"resource_ids\":[\"oauth\"]," +
                        "\"authorized_grant_types\":[\"client_credentials\"]," +
                        "\"redirect_uri\":[\"http://example.redirect.com\"]," +
                        "\"authorities\":[\"password.write\",\"scim.write\",\"scim.read\",\"oauth.approvals\"]" +
                        "}",
                uaaUrl + "/oauth/clients"
        );
    }

    public void createUser(String scimAccessToken, String userName, String email, String password, Boolean verified) throws Exception {

        restfulCreate(
                scimAccessToken,
                "{" +
                        "\"meta\":{\"version\":0,\"created\":\"2014-03-24T18:01:24.584Z\"}," +
                        "\"userName\":\"" + userName + "\"," +
                        "\"name\":{\"formatted\":\"Joe User\",\"familyName\":\"User\",\"givenName\":\"Joe\"}," +
                        "\"emails\":[{\"value\":\"" + email + "\"}]," +
                        "\"password\":\"" + password + "\"," +
                        "\"active\":true," +
                        "\"verified\":" + verified + "," +
                        "\"schemas\":[\"urn:scim:schemas:core:1.0\"]" +
                        "}",
                uaaUrl + "/Users"
        );
    }

    private void restfulCreate(String adminAccessToken, String json, String url) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + adminAccessToken);
        headers.add("Accept", "application/json");
        headers.add("Content-Type", "application/json");

        HttpEntity<String> requestEntity = new HttpEntity<String>(json, headers);
        ResponseEntity<Void> exchange = restTemplate.exchange(url, HttpMethod.POST, requestEntity, Void.class);
        Assert.assertEquals(HttpStatus.CREATED, exchange.getStatusCode());
    }


    public String extractLink(String messageBody) {
        Pattern linkPattern = Pattern.compile("<a href=\"(.*?)\">.*?</a>");
        Matcher matcher = linkPattern.matcher(messageBody);
        matcher.find();
        String encodedLink = matcher.group(1);
        return HtmlUtils.htmlUnescape(encodedLink);
    }
}
