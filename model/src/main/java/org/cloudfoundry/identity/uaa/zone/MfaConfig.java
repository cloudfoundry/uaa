package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class MfaConfig {

    private boolean enabled = false;
    private String providerName;
    private List<String> identityProviders = new ArrayList<>();
    public static final List<String> DEFAULT_MFA_IDENTITY_PROVIDERS = Arrays.asList("uaa", "ldap");


    @Override
    public String toString() {
        return "MfaConfig: {" +
                "enabled:" + enabled +
                ", providerName:\"" + providerName + '\"' +
                ", identityProviders:" + Arrays.toString(identityProviders.toArray()) +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        MfaConfig that = (MfaConfig) o;

        if (enabled != that.enabled) return false;
        return Objects.equals(providerName, that.providerName);
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

    public List<String> getIdentityProviders() {
        if (identityProviders == null || identityProviders.isEmpty()) {
            return DEFAULT_MFA_IDENTITY_PROVIDERS;
        }

        return identityProviders;
    }

    public void setIdentityProviders(List<String> identityProviders) {
        this.identityProviders = identityProviders;
    }

}
