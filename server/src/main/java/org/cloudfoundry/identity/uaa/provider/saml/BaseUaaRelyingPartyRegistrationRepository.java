package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneAware;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.util.List;
import java.util.Optional;

@Slf4j
public abstract class BaseUaaRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, ZoneAware {
    protected final String uaaWideSamlEntityID;
    protected final String uaaWideSamlEntityIDAlias;
    protected final String uaaWideSamlNameId;
    protected final List<SignatureAlgorithm> signatureAlgorithms;

    protected BaseUaaRelyingPartyRegistrationRepository(String uaaWideSamlEntityID, String uaaWideSamlEntityIDAlias,
            List<SignatureAlgorithm> signatureAlgorithms,
            String uaaWideSamlNameId) {
        this.uaaWideSamlEntityID = uaaWideSamlEntityID;
        this.uaaWideSamlEntityIDAlias = uaaWideSamlEntityIDAlias;
        this.signatureAlgorithms = signatureAlgorithms;
        this.uaaWideSamlNameId = uaaWideSamlNameId;
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
                // otherwise, construct a default value using the zone subdomain & uaa wide entityID
                .orElseGet(
                        () -> getDefaultZoneEntityId(currentZone.getSubdomain(), uaaWideSamlEntityID)
                );
    }

    private String getDefaultZoneEntityId(String zoneSubdomain, String uaaWideSamlEntityID) {
        if (UaaUrlUtils.isUrl(uaaWideSamlEntityID)) {
            return UaaUrlUtils.addSubdomainToUrl(uaaWideSamlEntityID, zoneSubdomain);
        } else {
            return "%s.%s".formatted(zoneSubdomain, uaaWideSamlEntityID);
        }
    }

    String getZoneEntityIdAlias(IdentityZone currentZone) {
        String alias = Optional.ofNullable(uaaWideSamlEntityIDAlias)
                .orElse(uaaWideSamlEntityID);

        // for default zone, use the samlEntityIDAlias if it exists, otherwise samlEntityID
        if (currentZone.isUaa()) {
            return alias;
        }
        // for non-default zone, construct a value using the zone subdomain & alias
        if (UaaUrlUtils.isUrl(alias)) {
            return UaaUrlUtils.getHostForURI(UaaUrlUtils.addSubdomainToUrl(alias, currentZone.getSubdomain()));
        } else {
            return "%s.%s".formatted(currentZone.getSubdomain(), alias);
        }
    }
}
