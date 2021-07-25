/*******************************************************************************
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
import java.util.List;
import java.util.Objects;


@JsonIgnoreProperties(ignoreUnknown = true)
public class OIDCIdentityProviderDefinition extends AbstractExternalOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition>
implements Cloneable {
    private URL discoveryUrl;
    private boolean passwordGrantEnabled = false;
    private boolean setForwardHeader = false;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<Prompt> prompts = null;

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

    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        OIDCIdentityProviderDefinition that = (OIDCIdentityProviderDefinition) o;

        if (this.passwordGrantEnabled != that.passwordGrantEnabled) return false;
        if (this.setForwardHeader != that.setForwardHeader) return false;
        return Objects.equals(discoveryUrl, that.discoveryUrl);

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (discoveryUrl != null ? discoveryUrl.hashCode() : 0);
        result = 31 * result + (passwordGrantEnabled ? 1 : 0);
        result = 31 * result + (setForwardHeader ? 1 : 0);
        return result;
    }
}
