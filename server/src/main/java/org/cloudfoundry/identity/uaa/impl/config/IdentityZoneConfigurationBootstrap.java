/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.*;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;

import static java.util.Collections.EMPTY_MAP;
import static java.util.Objects.nonNull;
import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public class IdentityZoneConfigurationBootstrap implements InitializingBean {

    private TokenPolicy tokenPolicy;
    private IdentityZoneProvisioning provisioning;
    private boolean selfServiceLinksEnabled = true;
    private String homeRedirect = null;
    private Map<String,Object> selfServiceLinks;
    private List<String> logoutRedirectWhitelist;
    private String logoutRedirectParameterName;
    private String logoutDefaultRedirectUrl;
    private boolean logoutDisableRedirectParameter = true;
    private List<Prompt> prompts;

    private String samlSpPrivateKey;
    private String samlSpPrivateKeyPassphrase;
    private String samlSpCertificate;

    private Map<String, Map<String, String>> samlKeys;
    private String activeKeyId;

    private boolean idpDiscoveryEnabled = false;

    private boolean accountChooserEnabled;

    @Autowired
    private IdentityZoneValidator validator = (config, mode) -> config;
    private Map<String, Object> branding;

    public void setValidator(IdentityZoneValidator validator) {
        this.validator = validator;
    }

    public IdentityZoneConfigurationBootstrap(IdentityZoneProvisioning provisioning) {
        this.provisioning = provisioning;
    }

    @Override
    public void afterPropertiesSet() throws InvalidIdentityZoneDetailsException {
        IdentityZone identityZone = provisioning.retrieve(IdentityZone.getUaa().getId());
        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(tokenPolicy);
        definition.getLinks().getSelfService().setSelfServiceLinksEnabled(selfServiceLinksEnabled);
        definition.getLinks().setHomeRedirect(homeRedirect);
        definition.getSamlConfig().setCertificate(samlSpCertificate);
        definition.getSamlConfig().setPrivateKey(samlSpPrivateKey);
        definition.getSamlConfig().setPrivateKeyPassword(samlSpPrivateKeyPassphrase);
        definition.setIdpDiscoveryEnabled(idpDiscoveryEnabled);
        definition.setAccountChooserEnabled(accountChooserEnabled);

        samlKeys = ofNullable(samlKeys).orElse(EMPTY_MAP);
        for (Map.Entry<String, Map<String,String>> entry : samlKeys.entrySet()) {
            SamlKey samlKey = new SamlKey(entry.getValue().get("key"), entry.getValue().get("passphrase"), entry.getValue().get("certificate"));
            definition.getSamlConfig().addKey(entry.getKey(), samlKey);
        }
        definition.getSamlConfig().setActiveKeyId(this.activeKeyId);

        if (selfServiceLinks!=null) {
            String signup = (String)selfServiceLinks.get("signup");
            String passwd = (String)selfServiceLinks.get("passwd");
            if (hasText(signup)) {
                definition.getLinks().getSelfService().setSignup(signup);
            }
            if (hasText(passwd)) {
                definition.getLinks().getSelfService().setPasswd(passwd);
            }
        }
        if (nonNull(logoutRedirectWhitelist)) {
            definition.getLinks().getLogout().setWhitelist(logoutRedirectWhitelist);
        }
        if (hasText(logoutRedirectParameterName)) {
            definition.getLinks().getLogout().setRedirectParameterName(logoutRedirectParameterName);
        }
        if (hasText(logoutDefaultRedirectUrl)) {
            definition.getLinks().getLogout().setRedirectUrl(logoutDefaultRedirectUrl);
        }
        definition.getLinks().getLogout().setDisableRedirectParameter(logoutDisableRedirectParameter);
        if (nonNull(prompts)) {
            definition.setPrompts(prompts);
        }

        BrandingInformation brandingInfo = JsonUtils.convertValue(branding, BrandingInformation.class);
        definition.setBranding(brandingInfo);

        identityZone.setConfig(definition);

        identityZone = validator.validate(identityZone, IdentityZoneValidator.Mode.MODIFY);
        provisioning.update(identityZone);
    }


    public IdentityZoneConfigurationBootstrap setSamlKeys(Map<String, Map<String, String>> samlKeys) {
        this.samlKeys = samlKeys;
        return this;
    }

    public IdentityZoneConfigurationBootstrap setActiveKeyId(String activeKeyId) {
        this.activeKeyId = activeKeyId;
        return this;
    }

    public void setTokenPolicy(TokenPolicy tokenPolicy) {
        this.tokenPolicy = tokenPolicy;
    }

    public void setSelfServiceLinksEnabled(boolean selfServiceLinksEnabled) {
        this.selfServiceLinksEnabled = selfServiceLinksEnabled;
    }

    public void setHomeRedirect(String homeRedirect) {
        this.homeRedirect = homeRedirect;
    }

    public String getHomeRedirect() {
        return homeRedirect;
    }

    public void setSelfServiceLinks(Map<String, Object> links) {
        this.selfServiceLinks = links;
    }

    public void setLogoutDefaultRedirectUrl(String logoutDefaultRedirectUrl) {
        this.logoutDefaultRedirectUrl = logoutDefaultRedirectUrl;
    }

    public void setLogoutDisableRedirectParameter(boolean logoutDisableRedirectParameter) {
        this.logoutDisableRedirectParameter = logoutDisableRedirectParameter;
    }

    public void setLogoutRedirectParameterName(String logoutRedirectParameterName) {
        this.logoutRedirectParameterName = logoutRedirectParameterName;
    }

    public void setLogoutRedirectWhitelist(List<String> logoutRedirectWhitelist) {
        this.logoutRedirectWhitelist = logoutRedirectWhitelist;
    }

    public void setPrompts(List<Prompt> prompts) {
        this.prompts = prompts;
    }

    public void setSamlSpCertificate(String samlSpCertificate) {
        this.samlSpCertificate = samlSpCertificate;
    }

    public void setSamlSpPrivateKey(String samlSpPrivateKey) {
        this.samlSpPrivateKey = samlSpPrivateKey;
    }

    public void setSamlSpPrivateKeyPassphrase(String samlSpPrivateKeyPassphrase) {
        this.samlSpPrivateKeyPassphrase = samlSpPrivateKeyPassphrase;
    }

    public boolean isIdpDiscoveryEnabled() {
        return idpDiscoveryEnabled;
    }

    public void setIdpDiscoveryEnabled(boolean idpDiscoveryEnabled) {
        this.idpDiscoveryEnabled = idpDiscoveryEnabled;
    }

    public boolean isAccountChooserEnabled() {
        return accountChooserEnabled;
    }

    public void setAccountChooserEnabled(boolean accountChooserEnabled) {
        this.accountChooserEnabled = accountChooserEnabled;
    }

    public void setBranding(Map<String, Object> branding) {
        this.branding = branding;
    }

    public Map<String, Object> getBranding() {
        return branding;
    }
}
