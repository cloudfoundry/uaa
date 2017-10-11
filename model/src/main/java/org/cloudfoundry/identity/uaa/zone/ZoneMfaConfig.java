package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ZoneMfaConfig {

    private boolean enabled = false;
    private String providerId = "";

    @Override
    public String toString() {
        return "ZoneMfaConfig: {" +
                "enabled:" + enabled +
                ", providerId:\"" + providerId + '\"' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ZoneMfaConfig that = (ZoneMfaConfig) o;

        if (enabled != that.enabled) return false;
        return providerId != null ? providerId.equals(that.providerId) : that.providerId == null;
    }

    @Override
    public int hashCode() {
        int result = (enabled ? 1 : 0);
        result = 31 * result + (providerId != null ? providerId.hashCode() : 0);
        return result;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public ZoneMfaConfig setEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public String getProviderId() {
        return providerId;
    }

    public ZoneMfaConfig setProviderId(String providerId) {
        this.providerId = providerId;
        return this;
    }
}
