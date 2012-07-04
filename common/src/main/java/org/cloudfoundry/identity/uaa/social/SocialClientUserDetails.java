/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.social;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Customized {@code UserDetails} implementation.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
public class SocialClientUserDetails extends User {

	private String email;
    private String name;
 	private Object id;

    public SocialClientUserDetails(String username, Collection<? extends GrantedAuthority> authorities) {
        super(username, "unused", authorities);
    }

    public String getEmail() {
        return email;
    }
    
	public Object getExternalId() {
		return id;
	}
	
	public void setExternalId(Object id) {
		this.id = id;
	}

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}

