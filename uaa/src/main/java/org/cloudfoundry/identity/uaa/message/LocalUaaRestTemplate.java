package org.cloudfoundry.identity.uaa.message;

import com.google.common.collect.Sets;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import javax.net.ssl.SSLContext;
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

    LocalUaaRestTemplate(
            @Qualifier("uaa") final OAuth2ProtectedResourceDetails resource,
            final AuthorizationServerTokenServices authorizationServerTokenServices,
            final MultitenantClientServices multitenantClientServices,
            @Value("${notifications.verify_ssl:false}") final boolean verifySsl,
            final IdentityZoneManager identityZoneManager)
            throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        super(resource);

        this.authorizationServerTokenServices = authorizationServerTokenServices;
        this.clientId = "login";
        this.multitenantClientServices = multitenantClientServices;
        this.identityZoneManager = identityZoneManager;

        if (!verifySsl) {
            skipSslValidation();
        }
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
        SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
        CloseableHttpClient httpClient = HttpClients.custom().setSslcontext(sslContext).build();
        ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        this.setRequestFactory(requestFactory);
    }
}
