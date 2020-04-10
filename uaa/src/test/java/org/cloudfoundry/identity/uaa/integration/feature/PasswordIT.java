
package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.util.LinkedMaskingMultiValueMap;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

import static org.junit.Assert.assertEquals;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class PasswordIT {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Test
    public void getClientCredentials() {
        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMaskingMultiValueMap<>();
        headers.add("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        RequestEntity requestEntity = new RequestEntity(headers, HttpMethod.POST, URI.create(baseUrl + "/oauth/token?client_id=client_with_bcrypt_prefix&client_secret=password&grant_type=client_credentials"));
        ResponseEntity<Void> responseEntity = restTemplate.exchange(requestEntity, Void.class);

        assertEquals(responseEntity.getStatusCodeValue(), 200);
    }

}
