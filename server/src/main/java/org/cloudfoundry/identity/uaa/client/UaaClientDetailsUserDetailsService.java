package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;

public class UaaClientDetailsUserDetailsService implements UserDetailsService {

    private final ClientDetailsService clientDetailsService;

    public UaaClientDetailsUserDetailsService(final ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UaaClientDetails clientDetails;
        try {
            clientDetails = (UaaClientDetails) clientDetailsService.loadClientByClientId(username);
        } catch (NoSuchClientException e) {
            throw new UsernameNotFoundException(e.getMessage(), e);
        }
        return new UaaClient(username, clientDetails.getClientSecret(), clientDetails.getAuthorities(), clientDetails.getAdditionalInformation(),
                clientDetails.getClientJwtConfig());
    }

}
