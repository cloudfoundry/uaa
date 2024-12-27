package org.cloudfoundry.identity.uaa.oauth.token.auth;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.AuthenticationScheme;
import org.springframework.http.HttpHeaders;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class DefaultClientAuthenticationHandler implements ClientAuthenticationHandler {

    public void authenticateTokenRequest(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form,
            HttpHeaders headers) {
        if (resource.isAuthenticationRequired()) {
            AuthenticationScheme scheme = Optional.ofNullable(resource.getClientAuthenticationScheme()).orElse(AuthenticationScheme.header);
            String clientSecret = Optional.ofNullable(resource.getClientSecret()).orElse("");
            if (AuthenticationScheme.header == scheme) {
                form.remove("client_secret");
                headers.add("Authorization", "Basic %s".formatted(
                        new String(Base64.getEncoder().encode("%s:%s".formatted(resource.getClientId(), clientSecret).getBytes(StandardCharsets.UTF_8)),
                                StandardCharsets.UTF_8)));
            } else {
                form.set("client_id", resource.getClientId());
                if (StringUtils.hasText(clientSecret)) {
                    form.set("client_secret", clientSecret);
                }
            }
        }
    }
}
