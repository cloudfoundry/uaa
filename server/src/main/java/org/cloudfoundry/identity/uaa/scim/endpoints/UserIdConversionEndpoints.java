package org.cloudfoundry.identity.uaa.scim.endpoints;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.resources.SearchResultsFactory;
import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.UaaPagingUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
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

import com.unboundid.scim.sdk.SCIMException;
import com.unboundid.scim.sdk.SCIMFilter;

@Controller
public class UserIdConversionEndpoints implements InitializingBean {
    private static final String FIELD_USERNAME = "userName";
    private static final String FIELD_ID = "id";
    private static final String FIELD_ORIGIN = "origin";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final ScimUserProvisioning scimUserProvisioning;
    private final SecurityContextAccessor securityContextAccessor;
    private final ScimUserEndpoints scimUserEndpoints;
    private final IdentityZoneManager identityZoneManager;
    private final boolean enabled;

    public UserIdConversionEndpoints(
            final SecurityContextAccessor securityContextAccessor,
            final ScimUserEndpoints scimUserEndpoints,
            final @Qualifier("scimUserProvisioning") ScimUserProvisioning scimUserProvisioning,
            final IdentityZoneManager identityZoneManager,
            final @Value("${scim.userids_enabled:true}") boolean enabled
    ) {
        this.securityContextAccessor = securityContextAccessor;
        this.scimUserEndpoints = scimUserEndpoints;
        this.scimUserProvisioning = scimUserProvisioning;
        this.identityZoneManager = identityZoneManager;
        this.enabled = enabled;
    }

    @RequestMapping(value = "/ids/Users")
    @ResponseBody
    public ResponseEntity<Object> findUsers(
            @RequestParam(defaultValue = "") String filter,
            @RequestParam(required = false, defaultValue = "ascending") final String sortOrder,
            @RequestParam(required = false, defaultValue = "1") int startIndex,
            @RequestParam(required = false, defaultValue = "100") int count,
            @RequestParam(required = false, defaultValue = "false") final boolean includeInactive
    ) {
        if (!enabled) {
            logger.info("Request from user {} received at disabled Id translation endpoint with filter:{}",
                    UaaStringUtils.getCleanedUserControlString(securityContextAccessor.getAuthenticationInfo()),
                    UaaStringUtils.getCleanedUserControlString(filter));
            return new ResponseEntity<>("Illegal Operation: Endpoint not enabled.", HttpStatus.BAD_REQUEST);
        }

        if (startIndex < 1) {
            startIndex = 1;
        }

        if (count > scimUserEndpoints.getUserMaxCount()) {
            count = scimUserEndpoints.getUserMaxCount();
        }

        filter = filter.trim();
        checkFilter(filter);

        // get all users for the given filter and the current page
        final boolean ascending = "ascending".equalsIgnoreCase(sortOrder);
        final List<ScimUser> filteredUsers;
        if (includeInactive) {
            filteredUsers = scimUserProvisioning.query(
                    filter, FIELD_USERNAME, ascending, identityZoneManager.getCurrentIdentityZoneId()
            );
        } else {
            filteredUsers = scimUserProvisioning.retrieveByScimFilterOnlyActive(
                    filter, FIELD_USERNAME, ascending, identityZoneManager.getCurrentIdentityZoneId()
            );
        }
        final List<ScimUser> usersCurrentPage = UaaPagingUtils.subList(filteredUsers, startIndex, count);

        // map to result structure
        final List<Map<String, String>> result = usersCurrentPage.stream()
                .map(scimUser -> Map.of(
                        FIELD_ID, scimUser.getId(),
                        FIELD_USERNAME, scimUser.getUserName(),
                        FIELD_ORIGIN, scimUser.getOrigin()
                ))
                .toList();

        return new ResponseEntity<>(
                SearchResultsFactory.buildSearchResultFrom(
                        result,
                        startIndex,
                        count,
                        filteredUsers.size(),
                        new String[]{FIELD_ID, FIELD_USERNAME, FIELD_ORIGIN},
                        Arrays.asList(ScimCore.SCHEMAS)
                ),
                HttpStatus.OK
        );
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
            if (!containsIdOrUserNameClause(scimFilter)) {
                throw new ScimException("Invalid filter attribute.", HttpStatus.BAD_REQUEST);
            }
        } catch (SCIMException e) {
            logger.debug("/ids/Users received an invalid filter [{}]", filter, e);
            throw new ScimException("Invalid filter '" + HtmlUtils.htmlEscape(filter) + "'", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Check if the given SCIM filter contains at least one clause involving either the "id" or "userName" property.
     */
    private boolean containsIdOrUserNameClause(SCIMFilter filter) {
        switch (filter.getFilterType()) {
            case AND, OR:
                // one of the operands must contain a comparison with the "id" or "userName" property
                final boolean resultLeftOperand = containsIdOrUserNameClause(filter.getFilterComponents().getFirst());
                return containsIdOrUserNameClause(filter.getFilterComponents().get(1)) || resultLeftOperand;
            case EQUALITY:
                String name = filter.getFilterAttribute().getAttributeName();
                if (FIELD_ID.equalsIgnoreCase(name) ||
                        FIELD_USERNAME.equalsIgnoreCase(name)) {
                    return true;
                } else if (FIELD_ORIGIN.equalsIgnoreCase(name)) {
                    return false;
                } else {
                    throw new ScimException("Invalid filter attribute.", HttpStatus.BAD_REQUEST);
                }
            case PRESENCE, STARTS_WITH, CONTAINS:
                throw new ScimException("Wildcards are not allowed in filter.", HttpStatus.BAD_REQUEST);
            case GREATER_THAN, GREATER_OR_EQUAL, LESS_THAN, LESS_OR_EQUAL:
                throw new ScimException("Invalid operator.", HttpStatus.BAD_REQUEST);
        }
        return false;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(scimUserEndpoints, "ScimUserEndpoints must be set");
    }
}
