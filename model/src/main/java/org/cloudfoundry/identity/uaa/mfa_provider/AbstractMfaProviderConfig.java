package org.cloudfoundry.identity.uaa.mfa_provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class AbstractMfaProviderConfig<T extends AbstractMfaProviderConfig<T>> {
    private String issuer;

    public static Class<? extends AbstractMfaProviderConfig> concreteMfaProviderConfigClass(MfaProvider.MfaProviderType type) {
        if(type == MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR) {
            return GoogleMfaProviderConfig.class;
        }
        throw new  IllegalArgumentException("Unknown MfaProvider.MfaProviderType: " + type);
    }

    public abstract void validate();

    public String getIssuer() {
        return issuer;
    }

    public T setIssuer(String issuer) {
        this.issuer = issuer;
        return (T) this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AbstractMfaProviderConfig<?> that = (AbstractMfaProviderConfig<?>) o;

        return issuer != null ? issuer.equals(that.issuer) : that.issuer == null;
    }

    @Override
    public int hashCode() {
        return issuer != null ? issuer.hashCode() : 0;
    }
}
