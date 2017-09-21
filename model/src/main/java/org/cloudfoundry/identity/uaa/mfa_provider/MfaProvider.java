package org.cloudfoundry.identity.uaa.mfa_provider;

import org.springframework.util.StringUtils;

public class MfaProvider {

    private String type;
    private String config;
    private String name;
    private Boolean active = true;
    public static final String GOOGLE_AUTH = "google-authenticator";


    public String getConfig() {
        return config;
    }

    public MfaProvider setConfig(String config) {
        this.config = config;
        return this;
    }

    public Boolean getActive() {
        return active;
    }

    public MfaProvider setActive(Boolean active) {
        this.active = active;
        return this;
    }

    public String getName() {
        return name;
    }

    public MfaProvider setName(String name) {
        this.name = name;
        return this;
    }

    public String getType() {
        return type;
    }

    public MfaProvider setType(String type) {
        this.type = type;
        return this;
    }

    public void validate() {
        if(!StringUtils.hasText(this.name)) {
            throw new IllegalArgumentException("Provider name cannot be empty");
        }
        if(!StringUtils.hasText(this.type) || !this.type.equals(GOOGLE_AUTH)) {
            throw new IllegalArgumentException("Provider type must be google-authenticator");
        }
        if(!StringUtils.hasText(config)) {
            throw new IllegalArgumentException("Provider config cannot be empty");
        }
    }
}