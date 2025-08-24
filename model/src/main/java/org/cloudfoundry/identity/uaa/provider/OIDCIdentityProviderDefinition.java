/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.cloudfoundry.identity.uaa.login.Prompt;

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.util.Collections.emptyMap;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OIDCIdentityProviderDefinition extends AbstractExternalOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition>
        implements Cloneable {
    private URL discoveryUrl;
    // Enable Resource Owner Password Grant flow for this identity provider.
    private boolean passwordGrantEnabled;
    // Set X-Forward-For header in Password Grant request to this identity provider.
    private boolean setForwardHeader;
    // Enable JWT Bearer Token Exchange Grant flow for this identity provider.
    private Boolean tokenExchangeEnabled;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<Prompt> prompts;
    // Enables private_key_jwt towards identity provider.
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Object jwtClientAuthentication;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    // Add additional parameters in request towards identity provider.
    private Map<String, String> additionalAuthzParameters;

    public URL getDiscoveryUrl() {
        return discoveryUrl;
    }

    public void setDiscoveryUrl(URL discoveryUrl) {
        this.discoveryUrl = discoveryUrl;
    }

    public boolean isPasswordGrantEnabled() {
        return passwordGrantEnabled;
    }

    public void setPasswordGrantEnabled(boolean passwordGrantEnabled) {
        this.passwordGrantEnabled = passwordGrantEnabled;
    }

    public boolean isSetForwardHeader() {
        return setForwardHeader;
    }

    public void setSetForwardHeader(boolean setForwardHeader) {
        this.setForwardHeader = setForwardHeader;
    }

    public List<Prompt> getPrompts() {
        return prompts;
    }

    public void setPrompts(List<Prompt> prompts) {
        this.prompts = prompts;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public Object getJwtClientAuthentication() {
        return this.jwtClientAuthentication;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public void setJwtClientAuthentication(final Object jwtClientAuthentication) {
        this.jwtClientAuthentication = jwtClientAuthentication;
    }

    public Map<String, String> getAdditionalAuthzParameters() {
        return this.additionalAuthzParameters != null ? Collections.unmodifiableMap(this.additionalAuthzParameters) : null;
    }

    public void setAdditionalAuthzParameters(final Map<String, String> additonalAuthzParameters) {
        this.additionalAuthzParameters = new HashMap<>(additonalAuthzParameters != null ? additonalAuthzParameters : emptyMap());
    }


    public Boolean isTokenExchangeEnabled() {
        return tokenExchangeEnabled;
    }

    public void setTokenExchangeEnabled(Boolean tokenExchangeEnabled) {
        this.tokenExchangeEnabled = tokenExchangeEnabled;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }

        OIDCIdentityProviderDefinition that = (OIDCIdentityProviderDefinition) o;

        if (this.passwordGrantEnabled != that.passwordGrantEnabled) {
            return false;
        }
        if (this.setForwardHeader != that.setForwardHeader) {
            return false;
        }
        if (!Objects.equals(this.jwtClientAuthentication, that.jwtClientAuthentication)) {
            return false;
        }
        if (!Objects.equals(this.additionalAuthzParameters, that.additionalAuthzParameters)) {
            return false;
        }
        if (!Objects.equals(this.tokenExchangeEnabled, that.tokenExchangeEnabled)) {
            return false;
        }
        return Objects.equals(discoveryUrl, that.discoveryUrl);

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (discoveryUrl != null ? discoveryUrl.hashCode() : 0);
        result = 31 * result + (passwordGrantEnabled ? 1 : 0);
        result = 31 * result + (setForwardHeader ? 1 : 0);
        result = 31 * result + (jwtClientAuthentication != null ? jwtClientAuthentication.hashCode() : 0);
        result = 31 * result + (additionalAuthzParameters != null ? additionalAuthzParameters.hashCode() : 0);
        result = 31 * result + (tokenExchangeEnabled != null ? tokenExchangeEnabled.hashCode() : 0);
        return result;
    }
}
