package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KeyProviderConfig {
    private String id;
    private String clientId;
    private String dcsTenantId;
    private String identityZoneId;

    public KeyProviderConfig() {
        this.clientId = null;
        this.dcsTenantId = null;
    }

    public KeyProviderConfig(String clientId, String dcsTenantId) {
        this.clientId = clientId;
        this.dcsTenantId = dcsTenantId;
    }

    public KeyProviderConfig(String id, String identityZoneId, String clientId, String dcsTenantId) {
        this.id = id;
        this.identityZoneId = identityZoneId;
        this.clientId = clientId;
        this.dcsTenantId = dcsTenantId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getDcsTenantId() {
        return dcsTenantId;
    }

    public void setDcsTenantId(String dcsTenantId) {
        this.dcsTenantId = dcsTenantId;
    }

    public String getIdentityZoneId() {
        return identityZoneId;
    }

    public void setIdentityZoneId(String zoneId) {
        this.identityZoneId = zoneId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyProviderConfig that = (KeyProviderConfig) o;
        return Objects.equals(clientId, that.clientId) &&
                Objects.equals(dcsTenantId, that.dcsTenantId) &&
                Objects.equals(identityZoneId, that.identityZoneId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, dcsTenantId, identityZoneId);
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
