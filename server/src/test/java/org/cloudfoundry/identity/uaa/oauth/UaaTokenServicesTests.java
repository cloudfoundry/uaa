package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Sets;
import org.bouncycastle.util.Strings;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.test.TestWebAppContext;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.EMPTY_LIST;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;


@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestWebAppContext.class)
public class UaaTokenServicesTests {
    @Autowired
    private UaaTokenServices tokenServices;

    @Value("${uaa.url}")
    private String uaaUrl;

    @Value("${oauth.clients.jku_test.id}")
    private String clientId;

    @Value("${oauth.clients.jku_test.secret}")
    private String clientSecret;

    @Value("${oauth.clients.jku_test.scope}")
    private String clientScopes;

    @Autowired
    private JdbcUaaUserDatabase jdbcUaaUserDatabase;

    @Test
    public void ensureJKUHeaderIsSetWhenBuildingAnAccessToken() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId, Arrays.asList(Strings.split(clientScopes, ',')));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        Jwt decode = JwtHelper.decode(accessToken.getValue());
        assertThat(decode.getHeader().getJku(), startsWith(uaaUrl));
        assertThat(decode.getHeader().getJku(), is("https://uaa.some.test.domain.com:555/uaa/token_keys"));
    }

    @Test
    public void ensureJKUHeaderIsSetWhenBuildingAnIdToken() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId, Arrays.asList("openid"));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        authorizationRequest.setResponseTypes(Sets.newHashSet("id_token"));
        authorizationRequest.setRequestParameters(azParameters);

        UaaUser uaaUser = jdbcUaaUserDatabase.retrieveUserByName("admin", "uaa");
        UaaPrincipal principal = new UaaPrincipal(uaaUser);
        UaaAuthentication userAuthentication = new UaaAuthentication(principal, null, EMPTY_LIST, null, true, System.currentTimeMillis());
        OAuth2Authentication auth2Authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);

        Jwt jwtToken = JwtHelper.decode(accessToken.getIdTokenValue());
        assertThat(jwtToken.getHeader().getJku(), startsWith(uaaUrl));
        assertThat(jwtToken.getHeader().getJku(), is("https://uaa.some.test.domain.com:555/uaa/token_keys"));
    }

    @Test
    public void ensureJKUHeaderIsSetWhenBuildingARefreshToken() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId, Arrays.asList("oauth.approvals"));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);

        UaaUser uaaUser = jdbcUaaUserDatabase.retrieveUserByName("admin", "uaa");
        UaaPrincipal principal = new UaaPrincipal(uaaUser);
        UaaAuthentication userAuthentication = new UaaAuthentication(principal, null, EMPTY_LIST, null, true, System.currentTimeMillis());
        OAuth2Authentication auth2Authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);

        Jwt jwtToken = JwtHelper.decode(accessToken.getRefreshToken().getValue());
        assertThat(jwtToken.getHeader().getJku(), startsWith(uaaUrl));
        assertThat(jwtToken.getHeader().getJku(), is("https://uaa.some.test.domain.com:555/uaa/token_keys"));
    }
}