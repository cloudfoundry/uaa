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
package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.util.StringUtils;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;


public class GeneralIdentityZoneConfigurationValidator implements IdentityZoneConfigurationValidator {

    private MfaConfigValidator mfaConfigValidator;

    @Override
    public IdentityZoneConfiguration validate(IdentityZone zone, IdentityZoneValidator.Mode mode) throws InvalidIdentityZoneConfigurationException {
        IdentityZoneConfiguration config = zone.getConfig();
        if (mode == IdentityZoneValidator.Mode.CREATE || mode == IdentityZoneValidator.Mode.MODIFY) {
            String currentKeyId = null;
            try {
                SamlConfig samlConfig;
                if ((samlConfig = config.getSamlConfig()) != null && samlConfig.getKeys().size()>0) {
                    String activeKeyId = samlConfig.getActiveKeyId();
                    if ( (activeKeyId == null || samlConfig.getKeys().get(activeKeyId) == null)) {

                        throw new InvalidIdentityZoneConfigurationException(String.format("Invalid SAML active key ID: '%s'. Couldn't find any matching keys.", activeKeyId));
                    }

                    for (Map.Entry<String, SamlKey> entry : samlConfig.getKeys().entrySet()) {
                        currentKeyId = entry.getKey();
                        String samlSpCert = entry.getValue().getCertificate();
                        String samlSpKey = entry.getValue().getKey();
                        String samlSpkeyPassphrase = entry.getValue().getPassphrase();
                        if (samlSpKey != null && samlSpCert != null) {
                            new KeyWithCert(samlSpKey, samlSpkeyPassphrase, samlSpCert);
                        }
                        failIfPartialCertKeyInfo(samlSpCert, samlSpKey, samlSpkeyPassphrase);
                    }
                }
            } catch (GeneralSecurityException ex) {
                throw new InvalidIdentityZoneConfigurationException(String.format("There is a security problem with the SAML SP Key configuration for key '%s'.", currentKeyId), ex);
            }

            TokenPolicy tokenPolicy = config.getTokenPolicy();
            if (tokenPolicy != null) {
                String activeKeyId = tokenPolicy.getActiveKeyId();
                if (StringUtils.hasText(activeKeyId)) {
                    Map<String, String> jwtKeys = tokenPolicy.getKeys();

                    if (jwtKeys == null || jwtKeys.isEmpty()) {
                        throw new InvalidIdentityZoneConfigurationException("Identity zone cannot specify an active key ID with no keys configured for the zone.", null);
                    } else {
                        if (!jwtKeys.containsKey(activeKeyId)) {
                            throw new InvalidIdentityZoneConfigurationException("The specified active key ID is not present in the configured keys: " + activeKeyId, null);
                        }
                    }
                }
            }
            if (!StringUtils.isEmpty(config.getIssuer())) {
                if (tokenPolicy == null || StringUtils.isEmpty(tokenPolicy.getActiveKeyId())) {
                    throw new InvalidIdentityZoneConfigurationException("You cannot set issuer value unless you have set your own signing key for this identity zone.");
                }
            }

            validateRegexStrings(config.getCorsPolicy().getXhrConfiguration().getAllowedUris(), "config.corsPolicy.xhrConfiguration.allowedUris");
            validateRegexStrings(config.getCorsPolicy().getXhrConfiguration().getAllowedOrigins(), "config.corsPolicy.xhrConfiguration.allowedOrigins");
            validateRegexStrings(config.getCorsPolicy().getDefaultConfiguration().getAllowedUris(), "config.corsPolicy.defaultConfiguration.allowedUris");
            validateRegexStrings(config.getCorsPolicy().getDefaultConfiguration().getAllowedOrigins(), "config.corsPolicy.defaultConfiguration.allowedOrigins");
        }

        if(config.getBranding() != null && config.getBranding().getConsent() != null) {
            ConsentValidator.validate(config.getBranding().getConsent());
        }

        if(config.getBranding() != null && config.getBranding().getBanner() != null) {
           BannerValidator.validate(config.getBranding().getBanner());
        }

        if(config.getMfaConfig() != null) {
            mfaConfigValidator.validate(config.getMfaConfig(), zone.getId());
        }

        return config;
    }

    private void validateRegexStrings(List<String> uris, String fieldName) throws InvalidIdentityZoneConfigurationException {
        if (uris != null) {
            for (String uri : uris) {
                try {
                    Pattern.compile(uri);
                } catch (PatternSyntaxException patternSyntaxException) {
                    throw new InvalidIdentityZoneConfigurationException(String.format("Invalid value in %s: '%s'.", fieldName, uri), patternSyntaxException);
                }
            }
        }
    }

    private void failIfPartialCertKeyInfo(String samlSpCert, String samlSpKey, String samlSpkeyPassphrase) throws InvalidIdentityZoneConfigurationException {
        if ((samlSpCert == null && samlSpKey == null && samlSpkeyPassphrase == null) ||
            (samlSpCert != null && samlSpKey != null && samlSpkeyPassphrase != null)) {
            return;
        }
        throw new InvalidIdentityZoneConfigurationException("Identity zone cannot be udpated with partial Saml CertKey config.", null);
    }

    public GeneralIdentityZoneConfigurationValidator setMfaConfigValidator(MfaConfigValidator mfaConfigValidator) {
        this.mfaConfigValidator = mfaConfigValidator;
        return this;
    }
}
