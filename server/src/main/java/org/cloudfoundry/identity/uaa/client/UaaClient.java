package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class UaaClient extends User {

    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private transient Map<String, Object> additionalInformation;

    private final String secret;
    private final String clientJwtConfig;

    public UaaClient(String username, String password, Collection<? extends GrantedAuthority> authorities, Map<String, Object> additionalInformation,
            String clientJwtConfig) {
        super(username, password == null ? "" : password, authorities);
        this.additionalInformation = additionalInformation;
        this.secret = password;
        this.clientJwtConfig = clientJwtConfig;
    }

    public UaaClient(UserDetails userDetails, String secret) {
        super(userDetails.getUsername(), secret == null ? "" : secret, userDetails.isEnabled(), userDetails.isAccountNonExpired(),
                userDetails.isCredentialsNonExpired(), userDetails.isAccountNonLocked(), userDetails.getAuthorities());
        if (userDetails instanceof UaaClient client) {
            this.additionalInformation = client.getAdditionalInformation();
            this.clientJwtConfig = client.clientJwtConfig;
        } else {
            this.clientJwtConfig = null;
        }
        this.secret = secret;
    }

    public boolean isAllowPublic() {
        Object allowPublic = Optional.ofNullable(additionalInformation).map(e -> e.get(ClientConstants.ALLOW_PUBLIC)).orElse(Collections.emptyMap());
        return (allowPublic instanceof String s && Boolean.TRUE.toString().equalsIgnoreCase(s)) || (allowPublic instanceof Boolean && Boolean.TRUE.equals(allowPublic));
    }

    public Map<String, Object> getAdditionalInformation() {
        return this.additionalInformation;
    }

    public ClientJwtConfiguration getClientJwtConfiguration() {
        // Start with configuration from clientJwtConfig field
        ClientJwtConfiguration result = Optional.ofNullable(clientJwtConfig)
                .map(ClientJwtConfiguration::readValue)
                .orElse(new ClientJwtConfiguration());
        
        // For backward compatibility, also check for JWT credentials in additionalInformation
        if (additionalInformation != null) {
            // Check for top-level jwt_creds in additionalInformation
            Object jwtCredsValue = additionalInformation.get(ClientJwtConfiguration.JWT_CREDS);
            if (jwtCredsValue != null) {
                try {
                    ClientJwtConfiguration additionalConfig = new ClientJwtConfiguration();
                    if (jwtCredsValue instanceof String jwtCredential) {
                        additionalConfig.addJwtCredentials(ClientJwtCredential.parse(jwtCredential));
                    } else if (jwtCredsValue instanceof List<?> jwtCredsList) {
                        String jwtCredsJson = JsonUtils.writeValueAsString(jwtCredsList);
                        additionalConfig.addJwtCredentials(ClientJwtCredential.parse(jwtCredsJson));
                    }
                    result = ClientJwtConfiguration.merge(result, additionalConfig, false);
                } catch (Exception e) {
                    // Log but don't fail - graceful degradation for backward compatibility
                }
            }
            
            // Check for nested client_jwt_config.jwt_creds in additionalInformation
            Object clientJwtCredsValue = additionalInformation.get("client_jwt_config");
            if (clientJwtCredsValue instanceof Map clientJwtCredsMap) {
                Object nestedJwtCreds = clientJwtCredsMap.get(ClientJwtConfiguration.JWT_CREDS);
                if (nestedJwtCreds != null) {
                    try {
                        ClientJwtConfiguration nestedConfig = new ClientJwtConfiguration();
                        if (nestedJwtCreds instanceof String jwtCredential) {
                            nestedConfig.addJwtCredentials(ClientJwtCredential.parse(jwtCredential));
                        } else if (nestedJwtCreds instanceof List<?> jwtCredsList) {
                            String jwtCredsJson = JsonUtils.writeValueAsString(jwtCredsList);
                            nestedConfig.addJwtCredentials(ClientJwtCredential.parse(jwtCredsJson));
                        }
                        result = ClientJwtConfiguration.merge(result, nestedConfig, false);
                    } catch (Exception e) {
                        // Log but don't fail - graceful degradation for backward compatibility
                    }
                }
            }
        }
        
        return result != null ? result : new ClientJwtConfiguration();
    }

    /**
     * Allow to return a null password. Super class does not allow to omit a password, therefore use own method
     *
     * @return The password of the client, can be null if no secret is set
     */
    @Override
    public String getPassword() {
        return this.secret;
    }
}
