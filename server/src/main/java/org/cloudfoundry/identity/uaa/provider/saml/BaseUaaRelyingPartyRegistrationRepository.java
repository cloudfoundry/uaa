package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneAware;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.util.Optional;

@Slf4j
public abstract class BaseUaaRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, ZoneAware {
    protected final String uaaWideSamlEntityID;
    protected final String uaaWideSamlEntityIDAlias;

    protected BaseUaaRelyingPartyRegistrationRepository(String uaaWideSamlEntityID, String uaaWideSamlEntityIDAlias) {
        this.uaaWideSamlEntityID = uaaWideSamlEntityID;
        this.uaaWideSamlEntityIDAlias = uaaWideSamlEntityIDAlias;
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
}
