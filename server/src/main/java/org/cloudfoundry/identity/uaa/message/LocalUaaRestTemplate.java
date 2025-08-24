package org.cloudfoundry.identity.uaa.message;

import com.google.common.collect.Sets;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.cloudfoundry.identity.uaa.UaaProperties;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.NotificationsProperties;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.GrantedAuthority;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;

public class LocalUaaRestTemplate extends OAuth2RestTemplate {
    private final AuthorizationServerTokenServices authorizationServerTokenServices;
    private final String clientId;
    private final MultitenantClientServices multitenantClientServices;
    private final IdentityZoneManager identityZoneManager;

    public LocalUaaRestTemplate(
            UaaProperties.RootLevel uaaProperties,
            NotificationsProperties notificationsProperties,
            final AuthorizationServerTokenServices authorizationServerTokenServices,
            final MultitenantClientServices multitenantClientServices,
            final IdentityZoneManager identityZoneManager)
            throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        super(clientResourceDetails(uaaProperties.LOGIN_SECRET()));

        this.authorizationServerTokenServices = authorizationServerTokenServices;
        this.clientId = "login";
        this.multitenantClientServices = multitenantClientServices;
        this.identityZoneManager = identityZoneManager;

        if (!notificationsProperties.verify_ssl()) {
            skipSslValidation();
        }
    }

    static ClientCredentialsResourceDetails clientResourceDetails(String loginSecret) {
        var res = new ClientCredentialsResourceDetails();
        res.setClientId("uaa");
        res.setClientId("login");
        res.setClientSecret(loginSecret);
        return res;
    }

    @Override
    public OAuth2AccessToken acquireAccessToken(OAuth2ClientContext oauth2Context) throws UserRedirectRequiredException {
        OAuth2Request request = new OAuth2Request(
                buildRequestParameters(),
                clientId,
                new HashSet<>(),
                true,
                buildScopes(),
                Sets.newHashSet(OriginKeys.UAA),
                null,
                new HashSet<>(),
                new HashMap<>());
        OAuth2Authentication authentication = new OAuth2Authentication(request, null);
        OAuth2AccessToken result = authorizationServerTokenServices.createAccessToken(authentication);
        oauth2Context.setAccessToken(result);
        return result;
    }

    private Set<String> buildScopes() {
        ClientDetails client = multitenantClientServices.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());

        return client.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }

    private Map<String, String> buildRequestParameters() {
        Map<String, String> requestParameters = new HashMap<>();
        requestParameters.put(OAuth2Utils.CLIENT_ID, clientId);
        requestParameters.put(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        return requestParameters;
    }

    private void skipSslValidation() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        CloseableHttpClient httpClient = HttpClients.custom()
                .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                        .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                                .setSslContext(SSLContextBuilder.create()
                                        .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                                        .build())
                                .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                                .build())
                        .build())
                .build();
        ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        this.setRequestFactory(requestFactory);
    }
}
