package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.ZoneAware;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.List;

/**
 * A {@link RelyingPartyRegistrationRepository} that delegates to a list of other {@link RelyingPartyRegistrationRepository}
 * instances.
 */
public class DelegatingRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, ZoneAware {

    private final List<RelyingPartyRegistrationRepository> delegates;

    public DelegatingRelyingPartyRegistrationRepository(List<RelyingPartyRegistrationRepository> delegates) {
        Assert.notEmpty(delegates, "delegates cannot be empty");
        this.delegates = delegates;
    }

    public DelegatingRelyingPartyRegistrationRepository(RelyingPartyRegistrationRepository... delegates) {
        Assert.notEmpty(delegates, "delegates cannot be empty");
        this.delegates = Arrays.asList(delegates);
    }

    /**
     * Returns the relying party registration identified by the provided
     * {@code registrationId}, or {@code null} if not found.
     *
     * @param registrationId the registration identifier
     * @return the {@link RelyingPartyRegistration} if found, otherwise {@code null}
     */
    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        boolean isDefaultZone = retrieveZone().isUaa();
        for (RelyingPartyRegistrationRepository repository : this.delegates) {
            if (isDefaultZone || repository instanceof ZoneAware) {
                RelyingPartyRegistration registration = repository.findByRegistrationId(registrationId);
                if (registration != null) {
                    return registration;
                }
            }
        }
        return null;
    }
}
