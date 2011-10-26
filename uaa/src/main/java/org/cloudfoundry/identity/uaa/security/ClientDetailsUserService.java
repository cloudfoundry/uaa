package org.cloudfoundry.identity.uaa.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;

public class ClientDetailsUserService implements UserDetailsService {

	private ClientDetailsService clientDetailsService;

	public void setClientDetails(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	@Override
	public UserDetails loadUserByUsername(String username) {
		ClientDetails client = clientDetailsService.loadClientByClientId(username);
		return new User(username, client.getClientSecret(), client.getAuthorities());
	}

}
