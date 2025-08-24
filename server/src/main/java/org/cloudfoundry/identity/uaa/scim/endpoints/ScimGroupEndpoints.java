package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.jayway.jsonpath.JsonPathException;
import org.cloudfoundry.identity.uaa.resources.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.resources.SearchResultsFactory;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.util.UaaPagingUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.web.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.View;
import org.springframework.web.util.HtmlUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes.ZONE_MANAGING_SCOPE_REGEX;
import static org.springframework.util.StringUtils.hasText;

@Controller
public class ScimGroupEndpoints {

    private static final String E_TAG = "ETag";

    private final ScimGroupProvisioning dao;
    private final ScimGroupMembershipManager membershipManager;
    private final IdentityZoneManager identityZoneManager;

    private final JdbcScimGroupExternalMembershipManager externalMembershipManager;

    private final Map<Class<? extends Exception>, HttpStatus> statuses;
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final int groupMaxCount;
    private final HttpMessageConverter<?>[] messageConverters;

    public ScimGroupEndpoints(
            final ScimGroupProvisioning scimGroupProvisioning,
            final ScimGroupMembershipManager membershipManager,
            final IdentityZoneManager identityZoneManager,
            final @Value("${groupMaxCount:500}") int groupMaxCount,
            final @Qualifier("exceptionToStatusMap") Map<Class<? extends Exception>, HttpStatus> statuses,
            final @Qualifier("externalGroupMembershipManager") JdbcScimGroupExternalMembershipManager externalMembershipManager) {
        if (groupMaxCount <= 0) {
            throw new IllegalArgumentException(
                    "Invalid \"groupMaxCount\" value (got %d). Should be positive number.".formatted(groupMaxCount)
            );
        }

        this.dao = scimGroupProvisioning;
        this.membershipManager = membershipManager;
        this.identityZoneManager = identityZoneManager;
        this.groupMaxCount = groupMaxCount;
        this.statuses = statuses;
        this.externalMembershipManager = externalMembershipManager;
        this.messageConverters = new HttpMessageConverter<?>[]{
                new ExceptionReportHttpMessageConverter()
        };
    }

    private boolean isMember(ScimGroup group, String userId) {
        if (null == userId) {
            return true;
        }
        for (ScimGroupMember member : group.getMembers()) {
            if (member.getMemberId().equals(userId)) {
                return true;
            }
        }
        return false;
    }

    private List<ScimGroup> filterForCurrentUser(List<ScimGroup> input, int startIndex, int count, boolean includeMembers) {
        List<ScimGroup> response = new ArrayList<>();
        int expectedResponseSize = Math.min(count, input.size());
        boolean needMore = response.size() < expectedResponseSize;
        while (needMore && startIndex <= input.size()) {
            for (ScimGroup group : UaaPagingUtils.subList(input, startIndex, count)) {
                if (includeMembers) {
                    group.setMembers(membershipManager.getMembers(group.getId(),
                            false,
                            identityZoneManager.getCurrentIdentityZoneId()));
                }
                response.add(group);
                needMore = response.size() < expectedResponseSize;
                if (!needMore) {
                    break;
                }
            }
            startIndex += count;
        }
        return response;
    }

    @GetMapping({"/Groups"})
    @ResponseBody
    public SearchResults<?> listGroups(
            @RequestParam(value = "attributes", required = false) String attributesCommaSeparated,
            @RequestParam(required = false, defaultValue = "id pr") String filter,
            @RequestParam(required = false, defaultValue = "created") String sortBy,
            @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
            @RequestParam(required = false, defaultValue = "1") int startIndex,
            @RequestParam(required = false, defaultValue = "100") int count) {

        if (count > groupMaxCount) {
            count = groupMaxCount;
        }

        List<ScimGroup> result;
        try {
            result = dao.query(filter,
                    sortBy,
                    "ascending".equalsIgnoreCase(sortOrder),
                    identityZoneManager.getCurrentIdentityZoneId());
        } catch (IllegalArgumentException e) {
            throw new ScimException("Invalid filter expression: [" + HtmlUtils.htmlEscape(filter) + "]",
                    HttpStatus.BAD_REQUEST);
        }

        List<ScimGroup> input;
        if (!StringUtils.hasLength(attributesCommaSeparated)) {
            input = filterForCurrentUser(result, startIndex, count, true);
            return new SearchResults<>(Arrays.asList(ScimCore.SCHEMAS), input, startIndex, count,
                    result.size());
        }

        AttributeNameMapper mapper = new SimpleAttributeNameMapper(Collections.emptyMap());

        String[] attributes = attributesCommaSeparated.split(",");
        input = filterForCurrentUser(result, startIndex, count, Arrays.asList(attributes).contains("members"));

        try {
            return SearchResultsFactory.buildSearchResultFrom(input, startIndex, count, result.size(), attributes,
                    mapper, Arrays.asList(ScimCore.SCHEMAS));
        } catch (JsonPathException e) {
            throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping({"/Groups/External/list"})
    @ResponseBody
    @Deprecated
    public SearchResults<?> listExternalGroups(
            @RequestParam(required = false, defaultValue = "1") int startIndex,
            @RequestParam(required = false, defaultValue = "100") int count,
            @RequestParam(required = false, defaultValue = "") String filter) {
        return getExternalGroups(startIndex, count, filter, "", "");
    }

    @GetMapping({"/Groups/External"})
    @ResponseBody
    public SearchResults<?> getExternalGroups(
            @RequestParam(required = false, defaultValue = "1") int startIndex,
            @RequestParam(required = false, defaultValue = "100") int count,
            @RequestParam(required = false, defaultValue = "") String filter,
            @RequestParam(required = false, defaultValue = "") String origin,
            @RequestParam(required = false, defaultValue = "") String externalGroup) {

        if (hasText(filter)) {
            if (hasText(origin) || hasText(externalGroup)) {
                throw new ScimException(
                        "Deprecated filter parameter may not be used in conjunction with origin or externalGroup parameters",
                        HttpStatus.BAD_REQUEST);
            }
            SimpleSearchQueryConverter converter = new SimpleSearchQueryConverter();
            try {
                MultiValueMap<String, Object> filterData = converter.getFilterValues(filter,
                        Arrays.asList("origin", "externalgroup"));
                origin = (ofNullable(filterData.getFirst("origin")).orElse(origin)).toString();
                externalGroup = (ofNullable(filterData.getFirst("externalGroup")).orElse(externalGroup)).toString();
            } catch (IllegalArgumentException e) {
                throw new ScimException("Filter not supported, please use origin and externalGroup parameters",
                        e,
                        HttpStatus.BAD_REQUEST);
            }
        }

        List<ScimGroupExternalMember> result;
        try {
            result = new ArrayList(externalMembershipManager.getExternalGroupMappings(identityZoneManager.getCurrentIdentityZoneId()));
        } catch (IllegalArgumentException e) {
            throw new ScimException("Invalid filter expression: [" + filter + "]", e, HttpStatus.BAD_REQUEST);
        }
        final String filterOrigin = origin;
        final String filterGroup = externalGroup;
        result.removeIf(em -> hasText(filterOrigin) && !em.getOrigin().equals(filterOrigin));
        result.removeIf(em -> hasText(filterGroup) && !em.getExternalGroup().equals(filterGroup));

        return SearchResultsFactory.cropAndBuildSearchResultFrom(
                result,
                startIndex,
                count,
                result.size(),
                new String[]{"groupId", "displayName", "externalGroup", "origin"},
                Arrays.asList(ScimCore.SCHEMAS));
    }

    @PostMapping({"/Groups/External"})
    @ResponseBody
    @ResponseStatus(HttpStatus.CREATED)
    public ScimGroupExternalMember mapExternalGroup(@RequestBody ScimGroupExternalMember sgm) {
        try {
            String displayName = sgm.getDisplayName();
            String groupId = hasText(sgm.getGroupId()) ? sgm.getGroupId() : getGroupId(displayName);
            String externalGroup = hasText(sgm.getExternalGroup()) ? sgm.getExternalGroup().trim() : sgm.getExternalGroup();
            String origin = hasText(sgm.getOrigin()) ? sgm.getOrigin() : LDAP;
            return externalMembershipManager.mapExternalGroup(groupId,
                    externalGroup,
                    origin,
                    identityZoneManager.getCurrentIdentityZoneId());
        } catch (IllegalArgumentException e) {
            throw new ScimException(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (ScimResourceNotFoundException e) {
            throw new ScimException(e.getMessage(), HttpStatus.NOT_FOUND);
        } catch (MemberAlreadyExistsException e) {
            throw new ScimException(e.getMessage(), HttpStatus.CONFLICT);
        }
    }

    @DeleteMapping({"/Groups/External/groupId/{groupId}/externalGroup/{externalGroup}"})
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    @Deprecated
    public ScimGroupExternalMember deprecated2UnmapExternalGroup(@PathVariable String groupId, @PathVariable String externalGroup) {
        return unmapExternalGroup(groupId, externalGroup, null);
    }

    @DeleteMapping({"/Groups/External/groupId/{groupId}/externalGroup/{externalGroup}/origin/{origin}"})
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    public ScimGroupExternalMember unmapExternalGroup(@PathVariable String groupId,
            @PathVariable String externalGroup,
            @PathVariable String origin) {
        try {
            if (!hasText(origin)) {
                origin = LDAP;
            }
            return externalMembershipManager.unmapExternalGroup(groupId,
                    externalGroup.trim(),
                    origin,
                    identityZoneManager.getCurrentIdentityZoneId());
        } catch (IllegalArgumentException e) {
            throw new ScimException(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (ScimResourceNotFoundException e) {
            throw new ScimException(e.getMessage(), HttpStatus.NOT_FOUND);
        } catch (MemberAlreadyExistsException e) {
            throw new ScimException(e.getMessage(), HttpStatus.CONFLICT);
        }
    }

    @DeleteMapping({"/Groups/External/id/{groupId}/{externalGroup}"})
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    @Deprecated
    public ScimGroupExternalMember deprecatedUnmapExternalGroup(@PathVariable String groupId, @PathVariable String externalGroup) {
        return unmapExternalGroup(groupId, externalGroup, LDAP);
    }

    @DeleteMapping({"/Groups/External/displayName/{displayName}/externalGroup/{externalGroup}"})
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    @Deprecated
    public ScimGroupExternalMember unmapExternalGroupUsingName(@PathVariable String displayName, @PathVariable String externalGroup) {
        return unmapExternalGroupUsingName(displayName, externalGroup, LDAP);
    }

    @DeleteMapping({"/Groups/External/displayName/{displayName}/externalGroup/{externalGroup}/origin/{origin}"})
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    public ScimGroupExternalMember unmapExternalGroupUsingName(@PathVariable String displayName,
            @PathVariable String externalGroup,
            @PathVariable String origin) {
        try {
            if (!hasText(origin)) {
                origin = LDAP;
            }

            return externalMembershipManager.unmapExternalGroup(getGroupId(displayName),
                    externalGroup.trim(),
                    origin,
                    identityZoneManager.getCurrentIdentityZoneId());
        } catch (IllegalArgumentException e) {
            throw new ScimException(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (ScimResourceNotFoundException e) {
            throw new ScimException(e.getMessage(), HttpStatus.NOT_FOUND);
        } catch (MemberAlreadyExistsException e) {
            throw new ScimException(e.getMessage(), HttpStatus.CONFLICT);
        }
    }

    @DeleteMapping({"/Groups/External/{displayName}/{externalGroup}"})
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    @Deprecated
    public ScimGroupExternalMember deprecatedUnmapExternalGroupUsingName(@PathVariable String displayName, @PathVariable String externalGroup) {
        return unmapExternalGroupUsingName(displayName, externalGroup);
    }

    private String getGroupId(String displayName) {
        if (displayName == null || displayName.trim().isEmpty()) {
            throw new ScimException("Group not found, not name provided", HttpStatus.NOT_FOUND);
        }

        try {
            return dao.getByName(displayName, identityZoneManager.getCurrentIdentityZoneId()).getId();
        } catch (IncorrectResultSizeDataAccessException e) {
            throw new ScimException("Group not found:" + displayName, HttpStatus.NOT_FOUND);
        }
    }


    @GetMapping({"/Groups/{groupId}"})
    @ResponseBody
    public ScimGroup getGroup(@PathVariable String groupId, HttpServletResponse httpServletResponse) {
        String groupIdRequest = UaaStringUtils.getCleanedUserControlString(groupId);
        logger.debug("retrieving group with id: {}", groupIdRequest);
        ScimGroup group = dao.retrieve(groupIdRequest, identityZoneManager.getCurrentIdentityZoneId());
        group.setMembers(membershipManager.getMembers(groupIdRequest, false, identityZoneManager.getCurrentIdentityZoneId()));
        addETagHeader(httpServletResponse, group);
        return group;
    }

    @PostMapping({"/Groups"})
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public ScimGroup createGroup(@RequestBody ScimGroup group, HttpServletResponse httpServletResponse) {
        group.setZoneId(identityZoneManager.getCurrentIdentityZoneId());
        ScimGroup created = dao.create(group, identityZoneManager.getCurrentIdentityZoneId());
        if (group.getMembers() != null) {
            for (ScimGroupMember member : group.getMembers()) {
                try {
                    membershipManager.addMember(created.getId(),
                            member,
                            identityZoneManager.getCurrentIdentityZoneId());
                } catch (ScimException ex) {
                    logger.warn("Attempt to add invalid member: {} to group: {}", member.getMemberId(), created.getId(), ex);
                    dao.delete(created.getId(), created.getVersion(), identityZoneManager.getCurrentIdentityZoneId());
                    throw new InvalidScimResourceException("Invalid group member: " + member.getMemberId());
                }
            }
        }
        created.setMembers(membershipManager.getMembers(created.getId(),
                false,
                identityZoneManager.getCurrentIdentityZoneId()));
        addETagHeader(httpServletResponse, created);
        return created;
    }

    @PutMapping({"/Groups/{groupId}"})
    @ResponseBody
    public ScimGroup updateGroup(@RequestBody ScimGroup group, @PathVariable String groupId,
            @RequestHeader(value = "If-Match", required = false) String etag,
            HttpServletResponse httpServletResponse) {
        if (etag == null) {
            throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
        }
        String groupIdRequest = UaaStringUtils.getCleanedUserControlString(groupId);
        logger.debug("updating group: {}", groupIdRequest);
        int version = getVersion(groupIdRequest, etag);
        group.setVersion(version);
        ScimGroup existing = getGroup(groupIdRequest, httpServletResponse);
        try {
            group.setZoneId(identityZoneManager.getCurrentIdentityZoneId());
            ScimGroup updated = dao.update(groupIdRequest, group, identityZoneManager.getCurrentIdentityZoneId());
            if (group.getMembers() != null && !group.getMembers().isEmpty()) {
                membershipManager.updateOrAddMembers(updated.getId(),
                        group.getMembers(),
                        identityZoneManager.getCurrentIdentityZoneId());
            } else {
                membershipManager.removeMembersByGroupId(updated.getId(),
                        identityZoneManager.getCurrentIdentityZoneId());
            }
            updated.setMembers(membershipManager.getMembers(updated.getId(),
                    false,
                    identityZoneManager.getCurrentIdentityZoneId()));
            addETagHeader(httpServletResponse, updated);
            return updated;
        } catch (IncorrectResultSizeDataAccessException ex) {
            logger.error("Error updating group, restoring to previous state");
            // restore to correct state before reporting error
            existing.setVersion(getVersion(groupIdRequest, "*"));
            dao.update(groupIdRequest, existing, identityZoneManager.getCurrentIdentityZoneId());
            throw new ScimException(ex.getMessage(), ex, HttpStatus.CONFLICT);
        } catch (ScimResourceNotFoundException ex) {
            logger.error("Error updating group, restoring to previous state: {}", existing);
            // restore to correct state before reporting error
            existing.setVersion(getVersion(groupIdRequest, "*"));
            dao.update(groupIdRequest, existing, identityZoneManager.getCurrentIdentityZoneId());
            throw new ScimException(ex.getMessage(), ex, HttpStatus.BAD_REQUEST);
        }
    }

    @PatchMapping({"/Groups/{groupId}"})
    @ResponseBody
    public ScimGroup patchGroup(@RequestBody ScimGroup patch, @PathVariable
    String groupId,
            @RequestHeader(value = "If-Match", required = false) String etag,
            HttpServletResponse httpServletResponse) {
        if (etag == null) {
            throw new ScimException("Missing If-Match for PATCH", HttpStatus.BAD_REQUEST);
        }
        String groupIdRequest = UaaStringUtils.getCleanedUserControlString(groupId);
        logger.debug("patching group: {}", groupIdRequest);
        int version = getVersion(groupIdRequest, etag);
        patch.setVersion(version);
        ScimGroup current = getGroup(groupId, httpServletResponse);
        current.patch(patch);
        return updateGroup(current, groupId, etag, httpServletResponse);
    }

    @DeleteMapping({"/Groups/{groupId}"})
    @ResponseBody
    public ScimGroup deleteGroup(@PathVariable String groupId,
            @RequestHeader(value = "If-Match", required = false, defaultValue = "*") String etag,
            HttpServletResponse httpServletResponse) {
        ScimGroup group = getGroup(groupId, httpServletResponse);
        logger.debug("deleting group: {}", group);
        try {
            membershipManager.removeMembersByGroupId(group.getId(), identityZoneManager.getCurrentIdentityZoneId());
            membershipManager.removeMembersByMemberId(group.getId(), identityZoneManager.getCurrentIdentityZoneId());
            dao.delete(group.getId(), getVersion(group.getId(), etag), identityZoneManager.getCurrentIdentityZoneId());
        } catch (IncorrectResultSizeDataAccessException ex) {
            logger.debug("error deleting group", ex);
            throw new ScimException("error deleting group: %s".formatted(groupId), ex, HttpStatus.CONFLICT);
        }
        return group;
    }

    @PostMapping({"/Groups/zones"})
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    @Deprecated
    public ScimGroup addZoneManagers(@RequestBody ScimGroup group, HttpServletResponse httpServletResponse) {
        if (!group.getDisplayName().matches(ZONE_MANAGING_SCOPE_REGEX)) {
            throw new ScimException("Invalid group name.", HttpStatus.BAD_REQUEST);
        }
        if (group.getMembers() == null || group.getMembers().isEmpty()) {
            throw new ScimException("Invalid group members, you have to add at least one member.",
                    HttpStatus.BAD_REQUEST);
        }
        try {
            ScimGroup existing = getGroup(getGroupId(group.getDisplayName()), httpServletResponse);
            List<ScimGroupMember> newMembers = new LinkedList<>(existing.getMembers());
            //we have an existing group - add new memberships
            for (ScimGroupMember member : group.getMembers()) {
                if (!isMember(existing, member.getMemberId())) {
                    newMembers.add(member);
                }
            }
            existing.setMembers(newMembers);
            return updateGroup(existing, existing.getId(), String.valueOf(existing.getVersion()), httpServletResponse);
        } catch (ScimException ex) {
            if (ex.getStatus().equals(HttpStatus.NOT_FOUND)) {
                return createGroup(group, httpServletResponse);
            } else {
                throw ex;
            }
        }
    }

    @DeleteMapping({"/Groups/zones/{userId}/{zoneId}"})
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    @Deprecated
    public ScimGroup deleteZoneAdmin(@PathVariable String userId, @PathVariable String zoneId, HttpServletResponse httpServletResponse) {
        return deleteZoneScope(userId, zoneId, "admin", httpServletResponse);
    }

    @DeleteMapping({"/Groups/zones/{userId}/{zoneId}/{scope}"})
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    @Deprecated
    public ScimGroup deleteZoneScope(@PathVariable String userId,
            @PathVariable String zoneId,
            @PathVariable String scope,
            HttpServletResponse httpServletResponse) {

        String groupName = "zones." + zoneId + "." + scope;
        if (!groupName.matches(ZONE_MANAGING_SCOPE_REGEX)) {
            throw new ScimException("Invalid group name.", HttpStatus.BAD_REQUEST);
        }
        String groupId = getGroupId(groupName);
        ScimGroup group = getGroup(groupId, httpServletResponse);
        if (!hasText(userId) || !hasText(zoneId)) {
            throw new ScimException("User ID and Zone ID are required.", HttpStatus.BAD_REQUEST);
        }
        if (!isMember(group, userId)) {
            throw new ScimException("User is not a zone admin.", HttpStatus.NOT_FOUND);
        }
        List<ScimGroupMember> newZoneAdmins = new LinkedList<>();
        for (ScimGroupMember member : group.getMembers()) {
            if (!member.getMemberId().equals(userId)) {
                newZoneAdmins.add(member);
            }
        }
        group.setMembers(newZoneAdmins);
        return updateGroup(group, group.getId(), String.valueOf(group.getVersion()), httpServletResponse);
    }

    @RequestMapping({"/Groups/{groupId}/members/{memberId}", "/Groups/{groupId}/members/{memberId}/"})
    public ResponseEntity<ScimGroupMember> getGroupMembership(@PathVariable String groupId, @PathVariable String memberId) {
        ScimGroupMember membership = membershipManager.getMemberById(groupId,
                memberId,
                identityZoneManager.getCurrentIdentityZoneId());
        return new ResponseEntity<>(membership, HttpStatus.OK);
    }

    @GetMapping({"/Groups/{groupId}/members", "/Groups/{groupId}/members/"})
    public ResponseEntity<List<ScimGroupMember>> listGroupMemberships(@PathVariable String groupId,
            @RequestParam(required = false, defaultValue = "false") boolean returnEntities,
            @RequestParam(required = false, defaultValue = "", name = "filter") String deprecatedFilter) {
        dao.retrieve(groupId, identityZoneManager.getCurrentIdentityZoneId());
        List<ScimGroupMember> members = membershipManager.getMembers(groupId,
                returnEntities,
                identityZoneManager.getCurrentIdentityZoneId());
        return new ResponseEntity<>(members, HttpStatus.OK);
    }

    @PostMapping({"/Groups/{groupId}/members", "/Groups/{groupId}/members/"})
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public ScimGroupMember addMemberToGroup(@PathVariable String groupId, @RequestBody ScimGroupMember member) {

        return membershipManager.addMember(groupId, member, identityZoneManager.getCurrentIdentityZoneId());
    }

    @DeleteMapping({"/Groups/{groupId}/members/{memberId}", "/Groups/{groupId}/members/{memberId}/"})
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    public ScimGroupMember deleteGroupMembership(@PathVariable String groupId, @PathVariable String memberId) {
        return membershipManager.removeMemberById(groupId, memberId, identityZoneManager.getCurrentIdentityZoneId());
    }

    @ExceptionHandler
    public View handleException(Exception t, HttpServletRequest request) throws ScimException {
        ScimException e = new ScimException("Unexpected error", t, HttpStatus.INTERNAL_SERVER_ERROR);
        if (t instanceof ScimException exception) {
            e = exception;
        } else {
            Class<?> clazz = t.getClass();
            //attempt to get the status directly first, before we browse the map
            HttpStatus status = statuses.get(clazz);
            if (status != null) {
                e = new ScimException(t.getMessage(), t, status);
            } else {
                for (Map.Entry<Class<? extends Exception>, HttpStatus> entry : statuses.entrySet()) {
                    if (entry.getKey().isAssignableFrom(clazz)) {
                        e = new ScimException(t.getMessage(), t, entry.getValue());
                        break;
                    }
                }
            }
        }
        // User can supply trace=true or just trace (unspecified) to get stack
        // traces
        boolean trace = request.getParameter("trace") != null && !"false".equals(request.getParameter("trace"));
        return new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(e, trace),
                e.getStatus()), messageConverters);
    }

    private int getVersion(String groupId, String etag) {
        String value = etag.trim();
        while (value.startsWith("\"")) {
            value = value.substring(1);
        }
        while (value.endsWith("\"")) {
            value = value.substring(0, value.length() - 1);
        }
        if ("*".equals(value)) {
            return dao.retrieve(groupId, identityZoneManager.getCurrentIdentityZoneId()).getVersion();
        }
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException e) {
            throw new ScimException("Invalid version match header (should be a version number): " + etag,
                    HttpStatus.BAD_REQUEST);
        }
    }

    private void addETagHeader(HttpServletResponse httpServletResponse, ScimGroup scimGroup) {
        httpServletResponse.setHeader(E_TAG, "\"" + scimGroup.getVersion() + "\"");
    }

}
