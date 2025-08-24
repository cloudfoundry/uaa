package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
public class IdentityZoneNotAvailableIT {

    private RestTemplate restTemplate;

    public static List<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"http://testzonedoesnotexist.localhost:8080/uaa"},
                {"http://testzoneinactive.localhost:8080/uaa"}
        });
    }

    @BeforeEach
    void setUp() {
        String[] scope = {"uaa.admin"};
        String baseUrl = "http://localhost:8080/uaa";
        ClientCredentialsResourceDetails adminResource = IntegrationTestUtils.getClientCredentialsResource(baseUrl, scope, "admin", "adminsecret");
        restTemplate = IntegrationTestUtils.getClientCredentialsTemplate(
                adminResource);
        restTemplate.setRequestFactory(new IntegrationTestUtils.StatelessRequestFactory());
        restTemplate.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
                // pass through
            }
        });
        IntegrationTestUtils.createInactiveIdentityZone(restTemplate, baseUrl);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: zoneUrl[{0}];")
    void tokenKeysEndpoint(String zoneUrl) {
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/token_keys");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: zoneUrl[{0}];")
    void tokenKeyEndpoint(String zoneUrl) {
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/token_key");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: zoneUrl[{0}];")
    void logoutDo(String zoneUrl) {
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/logout.do");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: zoneUrl[{0}];")
    void identityProvidersEndpoints(String zoneUrl) {
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/identity-providers");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/identity-providers");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/identity-providers/id");
        checkNotFoundForEndpoint(HttpMethod.PUT, zoneUrl + "/identity-providers/id");
        checkNotFoundForEndpoint(HttpMethod.DELETE, zoneUrl + "/identity-providers/id");
        checkNotFoundForEndpoint(HttpMethod.PATCH, zoneUrl + "/identity-providers/id/status");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: zoneUrl[{0}];")
    void usersEndpoints(String zoneUrl) {
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/Users/id");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/Users");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/Users");
        checkNotFoundForEndpoint(HttpMethod.PUT, zoneUrl + "/Users/id");
        checkNotFoundForEndpoint(HttpMethod.PATCH, zoneUrl + "/Users/id");
        checkNotFoundForEndpoint(HttpMethod.DELETE, zoneUrl + "/Users/id");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/userinfo");
        checkNotFoundForEndpoint(HttpMethod.PUT, zoneUrl + "/Users/id/password");
        checkNotFoundForEndpoint(HttpMethod.PATCH, zoneUrl + "/Users/id/status");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/Users/id/verify-link");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/Users/id/verify");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/ids/Users");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/invite_users");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: zoneUrl[{0}];")
    void groupsEndpoints(String zoneUrl) {
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/Groups/id");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/Groups");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/Groups");
        checkNotFoundForEndpoint(HttpMethod.PUT, zoneUrl + "/Groups/id");
        checkNotFoundForEndpoint(HttpMethod.PATCH, zoneUrl + "/Groups/id");
        checkNotFoundForEndpoint(HttpMethod.DELETE, zoneUrl + "/Groups/id");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/Groups/id1/members/id2");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/Groups/id1/members");
        checkNotFoundForEndpoint(HttpMethod.DELETE, zoneUrl + "/Groups/id1/members/id2");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/Groups/id1/members");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/Groups/External");
        checkNotFoundForEndpoint(HttpMethod.DELETE, zoneUrl + "/Groups/External/groupId/id");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/Groups/External");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: zoneUrl[{0}];")
    void clientsEndpoints(String zoneUrl) {
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/oauth/clients/id");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/oauth/clients");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/oauth/clients");
        checkNotFoundForEndpoint(HttpMethod.PUT, zoneUrl + "/oauth/clients/id");
        checkNotFoundForEndpoint(HttpMethod.DELETE, zoneUrl + "/oauth/clients/id");
        checkNotFoundForEndpoint(HttpMethod.PUT, zoneUrl + "/oauth/clients/id/secret");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/oauth/clients/tx");
        checkNotFoundForEndpoint(HttpMethod.PUT, zoneUrl + "/oauth/clients/tx");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/oauth/clients/tx/secret");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/oauth/clients/tx/modify");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/oauth/clients/tx/delete");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/oauth/clients/id/meta");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/oauth/clients/meta");
        checkNotFoundForEndpoint(HttpMethod.PUT, zoneUrl + "/oauth/clients/id/meta");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: zoneUrl[{0}];")
    void serverInformationEndpoints(String zoneUrl) {
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/info");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/passcode");
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/autologin");
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/autologin");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: zoneUrl[{0}];")
    void externalLoginServerEndpoints(String zoneUrl) {
        checkNotFoundForEndpoint(HttpMethod.POST, zoneUrl + "/password_resets");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: zoneUrl[{0}];")
    void staticContentFound(String zoneUrl) {
        HttpMethod method = HttpMethod.GET;
        String endpoint = zoneUrl + "/resources/oss/stylesheets/application.css";

        ResponseEntity<Void> forEntity = restTemplate.exchange(endpoint, method, new HttpEntity<Void>(null, new HttpHeaders()), Void.class);
        assertThat(forEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private void checkNotFoundForEndpoint(HttpMethod method, String endpoint) {
        ResponseEntity<Void> forEntity = restTemplate.exchange(endpoint, method, new HttpEntity<Void>(null, new HttpHeaders()), Void.class);
        assertThat(forEntity.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
