package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class MfaConfig {

    private boolean enabled = false;
    private String providerName;

    @Override
    public String toString() {
        return "MfaConfig: {" +
                "enabled:" + enabled +
                ", providerName:\"" + providerName + '\"' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        MfaConfig that = (MfaConfig) o;

        if (enabled != that.enabled) return false;
        return providerName != null ? providerName.equals(that.providerName) : that.providerName == null;
    }

    @Override
    public int hashCode() {
        int result = (enabled ? 1 : 0);
        result = 31 * result + (providerName != null ? providerName.hashCode() : 0);
        return result;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public MfaConfig setEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public String getProviderName() {
        return providerName;
    }

    public MfaConfig setProviderName(String providerName) {
        this.providerName = providerName;
        return this;
    }
}
