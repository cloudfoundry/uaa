package org.cloudfoundry.identity.uaa.provider.saml;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.List;

/**
 * A {@link RelyingPartyRegistrationRepository} that proxies to a list of other {@link RelyingPartyRegistrationRepository}
 * instances.
 */
public class ProxyingRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {

    private final List<RelyingPartyRegistrationRepository> repositories;

    public ProxyingRelyingPartyRegistrationRepository(List<RelyingPartyRegistrationRepository> repositories) {
        Assert.notEmpty(repositories, "repositories cannot be empty");
        this.repositories = repositories;
    }

    public ProxyingRelyingPartyRegistrationRepository(RelyingPartyRegistrationRepository... repositories) {
        Assert.notEmpty(repositories, "repositories cannot be empty");
        this.repositories = Arrays.asList(repositories);
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
        for (RelyingPartyRegistrationRepository repository : this.repositories) {
            RelyingPartyRegistration registration = repository.findByRegistrationId(registrationId);
            if (registration != null) {
                return registration;
            }
        }
        return null;
    }
}
