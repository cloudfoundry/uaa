package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.unboundid.scim.sdk.SCIMException;
import com.unboundid.scim.sdk.SCIMFilter;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.View;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Controller
public class UserIdConversionEndpoints implements InitializingBean {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final IdentityProviderProvisioning provisioning;
    private final SecurityContextAccessor securityContextAccessor;
    private final ScimUserEndpoints scimUserEndpoints;

    private boolean enabled;

    public UserIdConversionEndpoints(final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning,
                                     final SecurityContextAccessor securityContextAccessor,
                                     final ScimUserEndpoints scimUserEndpoints,
                                     final @Value("${scim.userids_enabled:true}") boolean enabled) {
        this.provisioning = provisioning;
        this.securityContextAccessor = securityContextAccessor;
        this.scimUserEndpoints = scimUserEndpoints;
        this.enabled = enabled;
    }

    @RequestMapping(value = "/ids/Users")
    @ResponseBody
    public ResponseEntity<Object> findUsers(
            @RequestParam(defaultValue = "") String filter,
            @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
            @RequestParam(required = false, defaultValue = "1") int startIndex,
            @RequestParam(required = false, defaultValue = "100") int count,
            @RequestParam(required = false, defaultValue = "false") boolean includeInactive) {
        if (!enabled) {
            logger.info("Request from user " + securityContextAccessor.getAuthenticationInfo() +
                    " received at disabled Id translation endpoint with filter:" + filter);
            return new ResponseEntity<>("Illegal Operation: Endpoint not enabled.", HttpStatus.BAD_REQUEST);
        }

        filter = filter.trim();
        checkFilter(filter);

        List<IdentityProvider> activeIdentityProviders = provisioning.retrieveActive(IdentityZoneHolder.get().getId());

        if (!includeInactive) {
            if (activeIdentityProviders.isEmpty()) {
                return new ResponseEntity<>(new SearchResults<>(Arrays.asList(ScimCore.SCHEMAS), new ArrayList<>(), startIndex, count, 0), HttpStatus.OK);
            }
            String originFilter = activeIdentityProviders.stream().map(identityProvider -> "".concat("origin eq \"" + identityProvider.getOriginKey() + "\"")).collect(Collectors.joining(" OR "));
            filter += " AND (" + originFilter + " )";
        }

        return new ResponseEntity<>(scimUserEndpoints.findUsers("id,userName,origin", filter, "userName", sortOrder, startIndex, count), HttpStatus.OK);
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
            throw new ScimException("Invalid filter '" + HtmlUtils.htmlEscape(filter) + "'", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Returns true if the field 'id' or 'userName' are present in the query.
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
    public void afterPropertiesSet() {
        Assert.notNull(scimUserEndpoints, "ScimUserEndpoints must be set");
    }
}
