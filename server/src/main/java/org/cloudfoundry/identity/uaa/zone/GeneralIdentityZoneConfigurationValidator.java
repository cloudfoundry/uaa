package org.cloudfoundry.identity.uaa.zone;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import org.cloudfoundry.identity.uaa.util.BoundedRegex;

import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.oauth.tls.MtlsTrustBundles;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

@Component
public class GeneralIdentityZoneConfigurationValidator implements IdentityZoneConfigurationValidator {

    private static final Logger logger = LoggerFactory.getLogger(GeneralIdentityZoneConfigurationValidator.class);

    public GeneralIdentityZoneConfigurationValidator() {
    }

    @Override
    public IdentityZoneConfiguration validate(IdentityZone zone, IdentityZoneValidator.Mode mode) throws InvalidIdentityZoneConfigurationException {
        IdentityZoneConfiguration config = zone.getConfig();
        if (mode == IdentityZoneValidator.Mode.CREATE || mode == IdentityZoneValidator.Mode.MODIFY) {
            try {
                MtlsTrustBundles.validate(config.getMtls().getTrustBundles());
            } catch (InvalidClientDetailsException e) {
                throw new InvalidIdentityZoneConfigurationException(e.getMessage(), e);
            }
            String currentKeyId = null;
            try {
                SamlConfig samlConfig;
                if ((samlConfig = config.getSamlConfig()) != null && !samlConfig.getKeys().isEmpty()) {
                    String activeKeyId = samlConfig.getActiveKeyId();
                    if (activeKeyId == null || samlConfig.getKeys().get(activeKeyId) == null) {

                        throw new InvalidIdentityZoneConfigurationException("Invalid SAML active key ID: '%s'. Couldn't find any matching keys.".formatted(activeKeyId));
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
                throw new InvalidIdentityZoneConfigurationException("There is a security problem with the SAML SP Key configuration for key '%s'.".formatted(currentKeyId), ex);
            }

            TokenPolicy tokenPolicy = config.getTokenPolicy();
            if (tokenPolicy != null) {
                if (tokenPolicy.isRefreshTokenRotate() &&
                        TokenConstants.TokenFormat.JWT.getStringValue().equalsIgnoreCase(tokenPolicy.getRefreshTokenFormat()) &&
                        !tokenPolicy.isJwtRevocable()) {
                    logger.warn("Invalid identity zone configuration: JWT-format refresh tokens with rotation enabled must be revocable. Auto-correcting to set jwtRevocable=true.");
                    tokenPolicy.setJwtRevocable(true);
                }
                String activeKeyId = tokenPolicy.getActiveKeyId();
                if (StringUtils.hasText(activeKeyId)) {
                    Map<String, TokenPolicy.KeyInformation> jwtKeys = tokenPolicy.getKeys();

                    if (jwtKeys == null || jwtKeys.isEmpty()) {
                        throw new InvalidIdentityZoneConfigurationException("Identity zone cannot specify an active key ID with no keys configured for the zone.", null);
                    } else {
                        if (!jwtKeys.containsKey(activeKeyId)) {
                            throw new InvalidIdentityZoneConfigurationException("The specified active key ID is not present in the configured keys: " + activeKeyId, null);
                        }
                    }
                }
            }
            if (!zone.isUaa() && UaaStringUtils.isNotEmpty(config.getIssuer()) && (tokenPolicy == null || UaaStringUtils.isNullOrEmpty(tokenPolicy.getActiveKeyId()))) {
                throw new InvalidIdentityZoneConfigurationException("You cannot set issuer value unless you have set your own signing key for this identity zone.");
            }

            validateRegexStrings(config.getCorsPolicy().getXhrConfiguration().getAllowedUris(), UnaryOperator.identity(), "config.corsPolicy.xhrConfiguration.allowedUris");
            validateRegexStrings(config.getCorsPolicy().getXhrConfiguration().getAllowedOrigins(), CorsConfiguration::anchorOrigin, "config.corsPolicy.xhrConfiguration.allowedOrigins");
            validateRegexStrings(config.getCorsPolicy().getDefaultConfiguration().getAllowedUris(), UnaryOperator.identity(), "config.corsPolicy.defaultConfiguration.allowedUris");
            validateRegexStrings(config.getCorsPolicy().getDefaultConfiguration().getAllowedOrigins(), CorsConfiguration::anchorOrigin, "config.corsPolicy.defaultConfiguration.allowedOrigins");

            UserConfigValidator.validate(config.getUserConfig());
        }

        if (config.getBranding() != null && config.getBranding().getConsent() != null) {
            ConsentValidator.validate(config.getBranding().getConsent());
        }

        if (config.getBranding() != null && config.getBranding().getBanner() != null) {
            BannerValidator.validate(config.getBranding().getBanner());
        }

        if (config.getBranding() != null && config.getBranding().getLoginConsent() != null) {
            List<String> errors = LoginConsentValidator.validate(config.getBranding().getLoginConsent());
            if (!errors.isEmpty()) {
                throw new InvalidIdentityZoneConfigurationException("Invalid login consent configuration: " + String.join(", ", errors), null);
            }
        }

        return config;
    }

    private void validateRegexStrings(List<String> uris, UnaryOperator<String> prepare, String fieldName) throws InvalidIdentityZoneConfigurationException {
        if (uris != null) {
            if (uris.size() > BoundedRegex.MAX_PATTERNS) {
                throw new InvalidIdentityZoneConfigurationException(
                        "Invalid value in %s: at most %d patterns are allowed.".formatted(fieldName, BoundedRegex.MAX_PATTERNS), null);
            }
            List<Pattern> compiled = new ArrayList<>();
            for (String uri : uris) {
                try {
                    compiled.add(BoundedRegex.compile(prepare.apply(UaaStringUtils.getCleanedUserControlString(uri))));
                } catch (PatternSyntaxException patternSyntaxException) {
                    throw new InvalidIdentityZoneConfigurationException("Invalid value in %s: '%s'.".formatted(fieldName, abbreviate(uri)), patternSyntaxException);
                }
            }
            if (!BoundedRegex.withinListLimits(compiled)) {
                throw new InvalidIdentityZoneConfigurationException(
                        "Invalid value in %s: the patterns together are too costly to evaluate.".formatted(fieldName), null);
            }
        }
    }

    private static String abbreviate(String value) {
        String cleaned = UaaStringUtils.getCleanedUserControlString(value);
        return cleaned != null && cleaned.length() > 100 ? cleaned.substring(0, 100) + "..." : cleaned;
    }

    private void failIfPartialCertKeyInfo(String samlSpCert, String samlSpKey, String samlSpkeyPassphrase) throws InvalidIdentityZoneConfigurationException {
        if ((samlSpCert == null && samlSpKey == null && samlSpkeyPassphrase == null) ||
                (samlSpCert != null && samlSpKey != null)) {
            return;
        }
        throw new InvalidIdentityZoneConfigurationException("Identity zone cannot be updated with partial Saml CertKey config.", null);
    }
}
