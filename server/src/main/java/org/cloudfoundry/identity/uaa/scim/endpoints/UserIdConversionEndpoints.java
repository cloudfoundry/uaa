/*******************************************************************************
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

package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.unboundid.scim.sdk.SCIMException;
import com.unboundid.scim.sdk.SCIMFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.security.beans.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.View;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Dave Syer
 * @author Luke Taylor
 *
 */
//@Controller
public class UserIdConversionEndpoints implements InitializingBean {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private SecurityContextAccessor securityContextAccessor;

    private  ScimUserEndpoints scimUserEndpoints;

    private IdentityProviderProvisioning provisioning;

    private boolean enabled = true;

    public UserIdConversionEndpoints(@Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning,
            SecurityContextAccessor securityContextAccessor,
            ScimUserEndpoints scimUserEndpoints ) {
        this.provisioning = provisioning;
        this.securityContextAccessor = securityContextAccessor;
        this.scimUserEndpoints = scimUserEndpoints;
    }

    /**
     * @param scimUserEndpoints the scimUserEndpoints to set
     */
    public void setScimUserEndpoints(ScimUserEndpoints scimUserEndpoints) {
        this.scimUserEndpoints = scimUserEndpoints;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Determines whether this endpoint is active or not.
     * If not enabled, it will return a 404.
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @RequestMapping(value = "/ids/Users")
    @ResponseBody
    public SearchResults<?> findUsers(
                    @RequestParam(required = true, defaultValue = "") String filter,
                    @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
                    @RequestParam(required = false, defaultValue = "1") int startIndex,
                    @RequestParam(required = false, defaultValue = "100") int count,
                    @RequestParam(required = false, defaultValue = "false") boolean includeInactive) {
        if (!enabled) {
            logger.warn("Request from user " + securityContextAccessor.getAuthenticationInfo() +
                            " received at disabled Id translation endpoint with filter:" + filter);
            throw new ScimException("Illegal operation.", HttpStatus.BAD_REQUEST);
        }

        filter = filter.trim();
        checkFilter(filter);

        List<IdentityProvider> activeIdentityProviders = provisioning.retrieveActive(IdentityZoneHolder.get().getId());

        if (!includeInactive) {
            if(activeIdentityProviders.isEmpty()) {
                return new SearchResults<>(Arrays.asList(ScimCore.SCHEMAS), new ArrayList<>(), startIndex, count, 0);
            }
            String originFilter = activeIdentityProviders.stream().map(identityProvider -> "".concat("origin eq \"" + identityProvider.getOriginKey() + "\"")).collect(Collectors.joining(" OR "));
            filter += " AND (" + originFilter + " )";
        }

        return scimUserEndpoints.findUsers("id,userName,origin", filter, "userName", sortOrder, startIndex, count);
    }

    @ExceptionHandler
    public View handleException(Exception t, HttpServletRequest request) throws ScimException {
        return scimUserEndpoints.handleException(t, request);
    }

    @ExceptionHandler(UnsupportedOperationException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public void handleException() {
    }

    private void checkFilter(String filter) {
        if (filter.isEmpty()) {
            throw new ScimException("a 'filter' parameter is required", HttpStatus.BAD_REQUEST);
        }
        SCIMFilter scimFilter;
        try {
            scimFilter = SCIMFilter.parse(filter);
            if (!checkFilter(scimFilter)) {
                throw new ScimException("Invalid filter attribute.", HttpStatus.BAD_REQUEST);
            }
        } catch (SCIMException e) {
            logger.debug("/ids/Users received an invalid filter [" + filter + "]", e);
            throw new ScimException("Invalid filter '"+filter+"'", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Returns true if the field 'id' or 'userName' are present in the query.
     * @param filter
     * @return
     */
    private boolean checkFilter(SCIMFilter filter) {
        switch (filter.getFilterType()) {
            case AND:
            case OR:
                return checkFilter(filter.getFilterComponents().get(0)) | checkFilter(filter.getFilterComponents().get(1));
            case EQUALITY:
                String name = filter.getFilterAttribute().getAttributeName();
                if ("id".equalsIgnoreCase(name) ||
                    "userName".equalsIgnoreCase(name)) {
                    return true;
                } else if (OriginKeys.ORIGIN.equalsIgnoreCase(name)) {
                    return false;
                } else {
                    throw new ScimException("Invalid filter attribute.", HttpStatus.BAD_REQUEST);
                }
            case PRESENCE:
            case STARTS_WITH:
            case CONTAINS:
                throw new ScimException("Wildcards are not allowed in filter.", HttpStatus.BAD_REQUEST);
            case GREATER_THAN:
            case GREATER_OR_EQUAL:
            case LESS_THAN:
            case LESS_OR_EQUAL:
                throw new ScimException("Invalid operator.", HttpStatus.BAD_REQUEST);
        }
        return false;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(scimUserEndpoints, "ScimUserEndpoints must be set");
    }
}
