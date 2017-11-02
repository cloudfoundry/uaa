package org.cloudfoundry.identity.uaa.mfa_provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class AbstractMfaProviderConfig {
    private String issuer;

    public abstract void validate();

    public String getIssuer() {
        return issuer;
    }

    public AbstractMfaProviderConfig setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AbstractMfaProviderConfig that = (AbstractMfaProviderConfig) o;

        return issuer != null ? issuer.equals(that.issuer) : that.issuer == null;
    }

    @Override
    public int hashCode() {
        return issuer != null ? issuer.hashCode() : 0;
    }
}
