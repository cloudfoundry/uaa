package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneAware;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.security.cert.CertificateException;
import java.util.List;
import java.util.Optional;

@Slf4j
public abstract class BaseUaaRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, ZoneAware {
    protected final String uaaWideSamlEntityID;
    protected final String uaaWideSamlEntityIDAlias;
    protected final List<KeyWithCert> defaultKeysWithCerts;

    protected BaseUaaRelyingPartyRegistrationRepository(String uaaWideSamlEntityID, String uaaWideSamlEntityIDAlias, List<KeyWithCert> defaultKeysWithCerts) {
        this.uaaWideSamlEntityID = uaaWideSamlEntityID;
        this.uaaWideSamlEntityIDAlias = uaaWideSamlEntityIDAlias;
        this.defaultKeysWithCerts = defaultKeysWithCerts;
    }

    String getZoneEntityId(IdentityZone currentZone) {
        // for default zone, use the samlEntityID
        if (currentZone.isUaa()) {
            return uaaWideSamlEntityID;
        }

        // for non-default zone, use the zone specific entityID, if it exists
        return Optional.ofNullable(currentZone.getConfig())
                .map(IdentityZoneConfiguration::getSamlConfig)
                .map(SamlConfig::getEntityID)
                // otherwise use the zone subdomain + default entityID
                .orElseGet(() -> "%s.%s".formatted(currentZone.getSubdomain(), uaaWideSamlEntityID));
    }

    String getZoneEntityIdAlias(IdentityZone currentZone) {
        String alias = Optional.ofNullable(uaaWideSamlEntityIDAlias)
                .orElse(uaaWideSamlEntityID);

        // for default zone, use the samlEntityIDAlias if it exists, otherwise samlEntityID
        if (currentZone.isUaa()) {
            return alias;
        }
        // for non-default zone, use the "zone subdomain+.+alias"
        return "%s.%s".formatted(currentZone.getSubdomain(), alias);
    }

    public List<KeyWithCert> convertToKeysWithCerts(List<SamlKey> samlKeys) {
        if (samlKeys == null) {
            return List.of();
        }

        try {
            return samlKeys.stream().map(k -> {
                try {
                    return new KeyWithCert(k);
                } catch (CertificateException e) {
                    log.error("Error converting key with cert", e);
                    throw new CertificateRuntimeException(e);
                }
            }).toList();
        } catch (CertificateRuntimeException e) {
            return List.of();
        }
    }
}
