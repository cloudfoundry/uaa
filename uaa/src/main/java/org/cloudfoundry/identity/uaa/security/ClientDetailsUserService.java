/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;

/**
 * A {@link UserDetailsService} that can be used to authenticate OAuth2 clients if they have been registered.
 * 
 * @author Dave Syer
 * 
 */
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
