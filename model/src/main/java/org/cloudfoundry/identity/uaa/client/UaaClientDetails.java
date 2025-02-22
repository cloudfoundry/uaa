package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.StringUtils;

import java.io.Serial;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Moved class BaseClient implementation of from spring-security-oauth2 into UAA
 *
 * {@link org.springframework.security.oauth2.provider.client.BaseClientDetails}.
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Extended this class with fields
 *  - client_jwt_config (supporting private_key_jwt)
 */
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
@JsonIgnoreProperties(ignoreUnknown = true)
public class UaaClientDetails implements ClientDetails {

    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_secret")
    private String clientSecret;

    @JsonDeserialize(using = Jackson2ArrayOrStringDeserializer.class)
    private Set<String> scope = Collections.emptySet();

    @JsonProperty("resource_ids")
    @JsonDeserialize(using = Jackson2ArrayOrStringDeserializer.class)
    private Set<String> resourceIds = Collections.emptySet();

    @JsonProperty("authorized_grant_types")
    @JsonDeserialize(using = Jackson2ArrayOrStringDeserializer.class)
    private Set<String> authorizedGrantTypes = Collections.emptySet();

    @JsonProperty("redirect_uri")
    @JsonDeserialize(using = Jackson2ArrayOrStringDeserializer.class)
    private Set<String> registeredRedirectUris;

    @JsonProperty("autoapprove")
    @JsonDeserialize(using = Jackson2ArrayOrStringDeserializer.class)
    private Set<String> autoApproveScopes;

    private List<GrantedAuthority> authorities = Collections.emptyList();

    @JsonProperty("access_token_validity")
    private Integer accessTokenValiditySeconds;

    @JsonProperty("refresh_token_validity")
    private Integer refreshTokenValiditySeconds;

    @com.fasterxml.jackson.annotation.JsonIgnore
    private transient Map<String, Object> additionalInformation = new LinkedHashMap<>();

    @JsonProperty("client_jwt_config")
    private String clientJwtConfig;

    public UaaClientDetails() {
    }

    public UaaClientDetails(ClientDetails prototype) {
        this();
        this.setAccessTokenValiditySeconds(prototype.getAccessTokenValiditySeconds());
        this.setRefreshTokenValiditySeconds(prototype.getRefreshTokenValiditySeconds());
        this.setAuthorities(prototype.getAuthorities());
        this.setAuthorizedGrantTypes(prototype.getAuthorizedGrantTypes());
        this.setClientId(prototype.getClientId());
        this.setClientSecret(prototype.getClientSecret());
        this.setRegisteredRedirectUri(prototype.getRegisteredRedirectUri());
        this.setScope(prototype.getScope());
        this.setResourceIds(prototype.getResourceIds());
        this.setAdditionalInformation(prototype.getAdditionalInformation());
    }

    public UaaClientDetails(String clientId, String resourceIds,
            String scopes, String grantTypes, String authorities, String redirectUris) {
        this.clientId = clientId;

        if (StringUtils.hasText(resourceIds)) {
            Set<String> resources = StringUtils
                    .commaDelimitedListToSet(resourceIds);
            if (!resources.isEmpty()) {
                this.resourceIds = resources;
            }
        }

        if (StringUtils.hasText(scopes)) {
            Set<String> scopeList = StringUtils.commaDelimitedListToSet(scopes);
            if (!scopeList.isEmpty()) {
                this.scope = scopeList;
            }
        }

        if (StringUtils.hasText(grantTypes)) {
            this.authorizedGrantTypes = StringUtils
                    .commaDelimitedListToSet(grantTypes);
        } else {
            this.authorizedGrantTypes = new HashSet<>(Arrays.asList(
                    "authorization_code", "refresh_token"));
        }

        if (StringUtils.hasText(authorities)) {
            this.authorities = AuthorityUtils
                    .commaSeparatedStringToAuthorityList(authorities);
        }

        if (StringUtils.hasText(redirectUris)) {
            this.registeredRedirectUris = StringUtils
                    .commaDelimitedListToSet(redirectUris);
        }
    }

    public UaaClientDetails(String clientId, String resourceIds,
            String scopes, String grantTypes, String authorities) {
        this(clientId, resourceIds, scopes, grantTypes, authorities, null);
    }

    @JsonIgnore
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setAutoApproveScopes(Collection<String> autoApproveScopes) {
        this.autoApproveScopes = new HashSet<>(autoApproveScopes);
    }

    @Override
    public boolean isAutoApprove(String scope) {
        if (autoApproveScopes == null) {
            return false;
        }
        for (String auto : autoApproveScopes) {
            if ("true".equals(auto) || auto.equals(scope)) {
                return true;
            }
        }
        return false;
    }

    @JsonIgnore
    public Set<String> getAutoApproveScopes() {
        return autoApproveScopes;
    }

    @JsonIgnore
    public boolean isSecretRequired() {
        return this.clientSecret != null;
    }

    @JsonIgnore
    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    @JsonIgnore
    public boolean isScoped() {
        return this.scope != null && !this.scope.isEmpty();
    }

    public Set<String> getScope() {
        return scope;
    }

    public void setScope(Collection<String> scope) {
        this.scope = scope == null ? Collections.emptySet() : scope.stream()
                .flatMap(s -> Arrays.stream(s.split(",")))
                .collect(Collectors.toSet());
    }

    @JsonIgnore
    public Set<String> getResourceIds() {
        return resourceIds;
    }

    public void setResourceIds(Collection<String> resourceIds) {
        this.resourceIds = resourceIds == null ? Collections.emptySet() : new LinkedHashSet<>(resourceIds);
    }

    @JsonIgnore
    public Set<String> getAuthorizedGrantTypes() {
        return authorizedGrantTypes;
    }

    public void setAuthorizedGrantTypes(Collection<String> authorizedGrantTypes) {
        this.authorizedGrantTypes = new LinkedHashSet<>(authorizedGrantTypes);
    }

    @JsonIgnore
    public Set<String> getRegisteredRedirectUri() {
        return registeredRedirectUris;
    }

    public void setRegisteredRedirectUri(Set<String> registeredRedirectUris) {
        this.registeredRedirectUris = registeredRedirectUris == null ? null
                : new LinkedHashSet<>(registeredRedirectUris);
    }

    @JsonProperty("authorities")
    private List<String> getAuthoritiesAsStrings() {
        return new ArrayList<>(AuthorityUtils.authorityListToSet(authorities));
    }

    @JsonProperty("authorities")
    @JsonDeserialize(using = Jackson2ArrayOrStringDeserializer.class)
    private void setAuthoritiesAsStrings(Set<String> values) {
        setAuthorities(AuthorityUtils.createAuthorityList(values
                .toArray(new String[values.size()])));
    }

    @JsonIgnore
    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @JsonIgnore
    public void setAuthorities(
            Collection<? extends GrantedAuthority> authorities) {
        this.authorities = new ArrayList<>(authorities);
    }

    @JsonIgnore
    public Integer getAccessTokenValiditySeconds() {
        return accessTokenValiditySeconds;
    }

    public void setAccessTokenValiditySeconds(Integer accessTokenValiditySeconds) {
        this.accessTokenValiditySeconds = accessTokenValiditySeconds;
    }

    @JsonIgnore
    public Integer getRefreshTokenValiditySeconds() {
        return refreshTokenValiditySeconds;
    }

    public void setRefreshTokenValiditySeconds(
            Integer refreshTokenValiditySeconds) {
        this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
    }

    public void setAdditionalInformation(Map<String, ?> additionalInformation) {
        this.additionalInformation = new LinkedHashMap<>(
                additionalInformation);
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalInformation() {
        return Collections.unmodifiableMap(this.additionalInformation);
    }

    @JsonAnySetter
    public void addAdditionalInformation(String key, Object value) {
        this.additionalInformation.put(key, value);
    }

    public String getClientJwtConfig() {
        return clientJwtConfig;
    }

    public void setClientJwtConfig(String clientJwtConfig) {
        this.clientJwtConfig = clientJwtConfig;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        UaaClientDetails other = (UaaClientDetails) obj;
        if (!Objects.equals(accessTokenValiditySeconds, other.accessTokenValiditySeconds)) {
            return false;
        }
        if (!Objects.equals(refreshTokenValiditySeconds, other.refreshTokenValiditySeconds)) {
            return false;
        }
        if (!Objects.equals(authorities, other.authorities)) {
            return false;
        }
        if (!Objects.equals(authorizedGrantTypes, other.authorizedGrantTypes)) {
            return false;
        }
        if (!Objects.equals(clientId, other.clientId)) {
            return false;
        }
        if (!Objects.equals(clientSecret, other.clientSecret)) {
            return false;
        }
        if (!Objects.equals(registeredRedirectUris, other.registeredRedirectUris)) {
            return false;
        }
        if (!Objects.equals(resourceIds, other.resourceIds)) {
            return false;
        }
        if (!Objects.equals(scope, other.scope)) {
            return false;
        }
        if (!Objects.equals(additionalInformation, other.additionalInformation)) {
            return false;
        }
        return Objects.equals(clientJwtConfig, other.clientJwtConfig);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime
                * result
                + (accessTokenValiditySeconds == null ? 0
                : accessTokenValiditySeconds);
        result = prime
                * result
                + (refreshTokenValiditySeconds == null ? 0
                : refreshTokenValiditySeconds);
        result = prime * result
                + (authorities == null ? 0 : authorities.hashCode());
        result = prime
                * result
                + (authorizedGrantTypes == null ? 0 : authorizedGrantTypes
                .hashCode());
        result = prime * result
                + (clientId == null ? 0 : clientId.hashCode());
        result = prime * result
                + (clientSecret == null ? 0 : clientSecret.hashCode());
        result = prime
                * result
                + (registeredRedirectUris == null ? 0
                : registeredRedirectUris.hashCode());
        result = prime * result
                + (resourceIds == null ? 0 : resourceIds.hashCode());
        result = prime * result + (scope == null ? 0 : scope.hashCode());
        result = prime * result + (additionalInformation == null ? 0 : additionalInformation.hashCode());
        result = prime * result + (clientJwtConfig == null ? 0 : clientJwtConfig.hashCode());
        return result;
    }
}
