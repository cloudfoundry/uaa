/*
 * *****************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.security.beans;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

/**
 * Encapsulation of security context access for use within the application.
 * 
 * Will be expanded as other requirements emerge.
 * 
 * @author Luke Taylor
 */
public interface SecurityContextAccessor {

    /**
     * Returns true if the current invocation is being made by
     * a client, not by or on behalf of (in the oauth sense) an end user.
     */
    boolean isClient();

    /**
     * Returns true if the current invocation is being made by
     * a user, not by a client app.
     */
    boolean isUser();

    /**
     * @return true if the user has the "admin" role
     */
    boolean isAdmin();

    /**
     * @return the current user identifier (not primary key)
     */
    String getUserId();

    /**
     * @return the current user name (the thing they login with)
     */
    String getUserName();

    /**
     * @return the current client identifier or null
     */
    String getClientId();

    /**
     * Provides a representation of the current user/client authentication
     * information for use in logs
     */
    String getAuthenticationInfo();

    /**
     * @return the authorities of the current principal (or empty if there is
     *         none)
     */
    Collection<? extends GrantedAuthority> getAuthorities();

    /**
     * @return the scopes of the current principal (or empty if there is
     *         none)
     */
    Collection<String> getScopes();

}
