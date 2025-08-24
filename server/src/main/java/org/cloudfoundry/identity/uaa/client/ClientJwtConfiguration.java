package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeyHelper;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientJwtConfiguration implements Cloneable {

    public static final String JWKS_URI = ClientJwtChangeRequest.JWKS_URI;
    public static final String JWKS = ClientJwtChangeRequest.JWKS;
    public static final String JWT_CREDS = "jwt_creds";

    @JsonIgnore
    private static final int MAX_KEY_SIZE = 10;

    @JsonProperty(JWKS_URI)
    private String jwksUri;

    @JsonProperty(JWKS)
    private JsonWebKeySet<JsonWebKey> jwkSet;

    @JsonProperty(JWT_CREDS)
    private List<ClientJwtCredential> clientJwtCredentials;

    public ClientJwtConfiguration() {
    }

    public ClientJwtConfiguration(final String jwksUri, final JsonWebKeySet<JsonWebKey> webKeySet) {
        this.jwksUri = jwksUri;
        jwkSet = webKeySet;
        if (jwkSet != null) {
            validateJwkSet();
        }
    }

    public ClientJwtConfiguration(List<ClientJwtCredential> clientJwtCredentials) {
        this.setClientJwtCredentials(clientJwtCredentials);
    }

    public String getJwksUri() {
        return this.jwksUri;
    }

    public void setJwksUri(final String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public JsonWebKeySet<JsonWebKey> getJwkSet() {
        return this.jwkSet;
    }

    public void setJwkSet(final JsonWebKeySet<JsonWebKey> jwkSet) {
        this.jwkSet = jwkSet;
    }

    public List<ClientJwtCredential> getClientJwtCredentials() {
        return this.clientJwtCredentials;
    }

    public void setClientJwtCredentials(final List<ClientJwtCredential> clientJwtCredentials) {
        this.clientJwtCredentials = setValidatedCredentials(clientJwtCredentials);
    }

    @JsonIgnore
    public void addJwtCredentials(final List<ClientJwtCredential> additionalCredentials) {
        HashMap<String, ClientJwtCredential> clientJwtCredentialHashMap = new HashMap<>();
        if (this.clientJwtCredentials != null) {
            this.clientJwtCredentials.forEach(jwtEntry -> clientJwtCredentialHashMap.putIfAbsent(jwtEntry.getSubject() + jwtEntry.getIssuer(), jwtEntry));
        }
        validateClientJwtCredentials(additionalCredentials, clientJwtCredentialHashMap);
        setClientJwtCredentials(clientJwtCredentialHashMap.values().stream().toList());
    }

    private static void validateClientJwtCredentials(List<ClientJwtCredential> additionalCredentials, HashMap<String, ClientJwtCredential> clientJwtCredentialHashMap) {
        additionalCredentials.forEach(jwtEntry ->
                clientJwtCredentialHashMap.putIfAbsent(jwtEntry.getSubject() + jwtEntry.getIssuer(), jwtEntry));
        if (clientJwtCredentialHashMap.isEmpty() || clientJwtCredentialHashMap.size() > MAX_KEY_SIZE) {
            throw new InvalidClientDetailsException("Invalid private_key_jwt: federated jwt credentials exceeds the maximum of keys. max: + " + MAX_KEY_SIZE);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        if (o instanceof ClientJwtConfiguration that) {
            if (!Objects.equals(jwksUri, that.jwksUri)) return false;
            if (!Objects.equals(clientJwtCredentials, that.clientJwtCredentials)) return false;
            if (jwkSet != null && that.jwkSet != null) {
                return jwkSet.getKeys().equals(that.jwkSet.getKeys());
            } else {
                return Objects.equals(jwkSet, that.jwkSet);
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();

        result = 31 * result + (jwksUri != null ? jwksUri.hashCode() : 0);
        result = 31 * result + (jwkSet != null ? jwkSet.hashCode() : 0);
        result = 31 * result + (clientJwtCredentials != null ? clientJwtCredentials.hashCode() : 0);
        return result;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    @JsonIgnore
    public boolean hasConfiguration() {
        boolean configurationChanges = false;
        try {
            if (UaaUrlUtils.isUrl(this.jwksUri)) {
                configurationChanges = true;
            } else if (this.jwkSet != null) {
                configurationChanges = !JWKSet.parse(this.jwkSet.getKeySetMap()).isEmpty();
            }
            if (!configurationChanges) {
                configurationChanges = !CollectionUtils.isEmpty(this.clientJwtCredentials);
            }
        } catch (IllegalStateException | JsonUtils.JsonUtilException | ParseException e) {
            throw new InvalidClientDetailsException("Client jwt configuration configuration fails ", e);
        }
        return configurationChanges;
    }

    @JsonIgnore
    public static ClientJwtConfiguration parse(String privateKeyConfig) {
        return UaaUrlUtils.isUrl(privateKeyConfig) ? parseJwksUri(privateKeyConfig) : parseJwkSet(privateKeyConfig);
    }

    @JsonIgnore
    public static ClientJwtConfiguration parse(String privateKeyUrl, String privateKeyJwt) {
        ClientJwtConfiguration clientJwtConfiguration = null;
        if (privateKeyUrl != null) {
            clientJwtConfiguration = parseJwksUri(privateKeyUrl);
        } else if (privateKeyJwt != null && privateKeyJwt.contains("{") && privateKeyJwt.contains("}")) {
            clientJwtConfiguration = parseJwkSet(privateKeyJwt);
        }
        return clientJwtConfiguration;
    }

    private static ClientJwtConfiguration parseJwkSet(String privateKeyJwt) {
        ClientJwtConfiguration clientJwtConfiguration;
        String cleanJwtString;
        try {
            HashMap<String, Object> jsonMap = JsonUtils.readValue(privateKeyJwt, HashMap.class);
            if (CollectionUtils.isEmpty(jsonMap)) {
                return new ClientJwtConfiguration();
            }
            if (jsonMap.containsKey("keys")) {
                cleanJwtString = JWKSet.parse(jsonMap).toString(true);
            } else {
                cleanJwtString = JWK.parse(jsonMap).toPublicJWK().toString();
            }
            clientJwtConfiguration = new ClientJwtConfiguration(null, JsonWebKeyHelper.deserialize(cleanJwtString));
            clientJwtConfiguration.validateJwkSet();
        } catch (ParseException | JsonUtils.JsonUtilException e) {
            throw new InvalidClientDetailsException("Client jwt configuration cannot be parsed", e);
        }
        return clientJwtConfiguration;
    }

    private static ClientJwtConfiguration parseJwksUri(String privateKeyUrl) {
        String normalizedUri;
        try {
            normalizedUri = UaaUrlUtils.normalizeUri(privateKeyUrl);
        } catch (IllegalArgumentException e) {
            throw new InvalidClientDetailsException("Client jwt configuration with invalid URI", e);
        }
        ClientJwtConfiguration clientJwtConfiguration = new ClientJwtConfiguration(normalizedUri, null);
        clientJwtConfiguration.validateJwksUri();
        return clientJwtConfiguration;
    }

    private boolean validateJwkSet() {
        List<JsonWebKey> keyList = jwkSet.getKeys();
        if (keyList.isEmpty() || keyList.size() > MAX_KEY_SIZE) {
            throw new InvalidClientDetailsException("Invalid private_key_jwt: jwk set is empty of exceeds to maximum of keys. max: + " + MAX_KEY_SIZE);
        }
        Set<String> keyId = new HashSet<>();
        keyList.forEach((JsonWebKey key) -> {
            if (!StringUtils.hasText(key.getKid())) {
                throw new InvalidClientDetailsException("Invalid private_key_jwt: kid is required attribute");
            }
            keyId.add(key.getKid());
        });
        if (keyId.size() != keyList.size()) {
            throw new InvalidClientDetailsException("Invalid private_key_jwt: duplicate kid in JWKSet not allowed");
        }
        return true;
    }

    private boolean validateJwksUri() {
        URI validateJwksUri;
        try {
            validateJwksUri = URI.create(this.jwksUri);
        } catch (IllegalArgumentException e) {
            throw new InvalidClientDetailsException("Invalid private_key_jwt: jwks_uri must be URI complaint", e);
        }
        if (!validateJwksUri.isAbsolute()) {
            throw new InvalidClientDetailsException("Invalid private_key_jwt: jwks_uri must be an absolute URL");
        }
        if (!"https".equals(validateJwksUri.getScheme()) && !"http".equals(validateJwksUri.getScheme())) {
            throw new InvalidClientDetailsException("Invalid private_key_jwt: jwks_uri must be either using https or http");
        }
        if ("http".equals(validateJwksUri.getScheme()) && !validateJwksUri.getHost().endsWith("localhost")) {
            throw new InvalidClientDetailsException("Invalid private_key_jwt: jwks_uri with http is not on localhost");
        }
        return true;
    }

    private List<ClientJwtCredential> setValidatedCredentials(List<ClientJwtCredential> clientJwtCredentials) {
        if (ObjectUtils.isEmpty(clientJwtCredentials)) {
            throw new InvalidClientDetailsException("Invalid null or empty credentials");
        }
        HashMap<String, ClientJwtCredential> clientJwtCredentialHashMap = new HashMap<>();
        validateClientJwtCredentials(clientJwtCredentials, clientJwtCredentialHashMap);
        return clientJwtCredentialHashMap.values().stream().toList();
    }

    /**
     * Creator from ClientDetails. Should abstract the persistence.
     * Use currently the client_jwt_config in UaaClientDetails
     */
    @JsonIgnore
    public static ClientJwtConfiguration readValue(UaaClientDetails clientDetails) {
        if (clientDetails == null ||
                clientDetails.getClientJwtConfig() == null ||
                !(clientDetails.getClientJwtConfig() instanceof String)) {
            return null;
        }
        return readValue(clientDetails.getClientJwtConfig());
    }

    /**
     * Creator from searialized ClientJwtConfiguration.
     */
    @JsonIgnore
    public static ClientJwtConfiguration readValue(String clientJwtConfig) {
        return JsonUtils.readValue(clientJwtConfig, ClientJwtConfiguration.class);
    }

    /**
     * Creator from ClientDetails. Should abstract the persistence.
     * Use currently the client_jwt_config in UaaClientDetails
     */
    @JsonIgnore
    public void writeValue(ClientDetails clientDetails) {
        if (clientDetails instanceof UaaClientDetails uaaClientDetails) {
            uaaClientDetails.setClientJwtConfig(JsonUtils.writeValueAsString(this));
        }
    }

    /**
     * Cleanup configuration in ClientDetails. Should abstract the persistence.
     * Use currently the client_jwt_config in UaaClientDetails
     */
    @JsonIgnore
    public static void resetConfiguration(ClientDetails clientDetails) {
        if (clientDetails instanceof UaaClientDetails uaaClientDetails) {
            uaaClientDetails.setClientJwtConfig(null);
        }
    }

    @JsonIgnore
    public static ClientJwtConfiguration merge(ClientJwtConfiguration existingConfig, ClientJwtConfiguration newConfig, boolean overwrite) {
        if (existingConfig == null) {
            return newConfig;
        }
        if (newConfig == null) {
            return existingConfig;
        }
        ClientJwtConfiguration result = null;
        if (newConfig.jwksUri != null) {
            if (overwrite) {
                result = new ClientJwtConfiguration(newConfig.jwksUri, null);
            } else {
                result = existingConfig;
                result.jwksUri = existingConfig.jwksUri != null ? existingConfig.jwksUri : newConfig.jwksUri;
            }
        }
        if (newConfig.jwkSet != null) {
            if (existingConfig.jwkSet == null) {
                if (overwrite) {
                    result = new ClientJwtConfiguration(null, newConfig.jwkSet);
                } else {
                    result = existingConfig;
                    result.jwkSet = newConfig.jwkSet;
                }
            } else {
                JsonWebKeySet<JsonWebKey> existingKeySet = existingConfig.jwkSet;
                List<JsonWebKey> existingKeys = new ArrayList<>(existingKeySet.getKeys());
                List<JsonWebKey> newKeys = new ArrayList<>();
                newConfig.getJwkSet().getKeys().forEach((JsonWebKey key) -> {
                    if (existingKeys.contains(key)) {
                        if (overwrite) {
                            existingKeys.remove(key);
                            newKeys.add(key);
                        }
                    } else {
                        newKeys.add(key);
                    }
                });
                existingKeys.addAll(newKeys);
                result = new ClientJwtConfiguration(null, new JsonWebKeySet<>(existingKeys));
            }
        }
        if (newConfig.clientJwtCredentials != null) {
            result = existingConfig;
            if (overwrite) {
                result.setValidatedCredentials(newConfig.clientJwtCredentials);
            } else {
                result.addJwtCredentials(newConfig.clientJwtCredentials);
            }
        }
        return result;
    }

    @JsonIgnore
    public static ClientJwtConfiguration delete(ClientJwtConfiguration existingConfig, ClientJwtConfiguration tobeDeleted) {
        if (existingConfig == null) {
            return null;
        }
        if (tobeDeleted == null) {
            return existingConfig;
        }
        ClientJwtConfiguration result = existingConfig;
        if (existingConfig.jwkSet != null && tobeDeleted.jwksUri != null) {
            JsonWebKeySet<JsonWebKey> existingKeySet = existingConfig.jwkSet;
            List<JsonWebKey> keys = existingKeySet.getKeys().stream().filter(k -> !tobeDeleted.jwksUri.equals(k.getKid())).toList();
            if (keys.isEmpty()) {
                result.jwkSet = null;
            } else {
                result = new ClientJwtConfiguration(null, new JsonWebKeySet<>(keys));
            }
        } else if (existingConfig.jwkSet != null && tobeDeleted.jwkSet != null) {
            List<JsonWebKey> existingKeys = new ArrayList<>(existingConfig.getJwkSet().getKeys());
            existingKeys.removeAll(tobeDeleted.jwkSet.getKeys());
            if (existingKeys.isEmpty()) {
                result.jwkSet = null;
            } else {
                result = new ClientJwtConfiguration(null, new JsonWebKeySet<>(existingKeys));
            }
        } else if (existingConfig.jwksUri != null && tobeDeleted.jwksUri != null) {
            if ("*".equals(tobeDeleted.jwksUri) || existingConfig.jwksUri.equals(tobeDeleted.jwksUri)) {
                result.jwksUri = null;
            }
        } else if (existingConfig.clientJwtCredentials != null && tobeDeleted.clientJwtCredentials != null) {
            existingConfig.clientJwtCredentials = existingConfig.clientJwtCredentials.stream()
                    .filter (c -> tobeDeleted.clientJwtCredentials.stream()
                    .noneMatch(e -> e.getSubject().equals(c.getSubject()) && e.getIssuer().equals(c.getIssuer()))).toList();
            if (ObjectUtils.isEmpty(result.clientJwtCredentials) || tobeDeleted.clientJwtCredentials.equals(List.of(new ClientJwtCredential("*", "*", null))) || tobeDeleted.clientJwtCredentials.equals(List.of(new ClientJwtCredential("*", "*", "*")))) {
                result.clientJwtCredentials = null;
            }
        }
        return ObjectUtils.isEmpty(result.jwkSet) && ObjectUtils.isEmpty(result.jwksUri) && ObjectUtils.isEmpty(result.clientJwtCredentials) ? null : result;
    }
}
