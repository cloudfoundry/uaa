package org.cloudfoundry.identity.uaa.mfa_provider;

public class MfaProviderConfig {

    private String providerDescription;
    private String issuer;
    private Integer digits;
    private Integer duration;
    private enum Algorithm {
        SHA256 ("SHA-256"),
        SHA512 ("SHA-512");
        private String value;
        Algorithm(String value) {
            this.value = value;
        }
    }


    public String getProviderDescription() {
        return providerDescription;
    }

    public void setProviderDescription(String providerDescription) {
        this.providerDescription = providerDescription;
    }

    public Integer getDigits() {
        return digits;
    }

    public void setDigits(Integer digits) {
        this.digits = digits;
    }

    public Integer getDuration() {
        return duration;
    }

    public void setDuration(Integer duration) {
        this.duration = duration;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
    public void validate() {

    }
}
