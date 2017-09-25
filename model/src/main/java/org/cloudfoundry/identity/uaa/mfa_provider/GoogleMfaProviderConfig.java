package org.cloudfoundry.identity.uaa.mfa_provider;


import org.springframework.util.StringUtils;

import static org.springframework.util.StringUtils.hasText;

public class GoogleMfaProviderConfig extends AbstractMfaProviderConfig<GoogleMfaProviderConfig> {

    public enum Algorithm { SHA256, SHA512 }

    private String providerDescription;
    private int digits = 6;
    private int duration = 30;
    private Algorithm algorithm = Algorithm.SHA256;


    public void validate() {
        if(!hasText(this.getIssuer())) {
            throw new IllegalArgumentException("Mfa provider must have issuer.");
        }
    }

    public String getProviderDescription() {
        return providerDescription;
    }

    public GoogleMfaProviderConfig setProviderDescription(String providerDescription) {
        this.providerDescription = providerDescription;
        return this;
    }

    public int getDigits() {
        return digits;
    }

    public GoogleMfaProviderConfig setDigits(int digits) {
        this.digits = digits;
        return this;
    }

    public int getDuration() {
        return duration;
    }

    public GoogleMfaProviderConfig setDuration(int duration) {
        this.duration = duration;
        return this;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public GoogleMfaProviderConfig setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }
}