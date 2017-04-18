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

import com.jayway.jsonpath.JsonPathException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.resources.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.resources.SearchResultsFactory;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
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
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.UaaPagingUtils;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes.ZONE_MANAGING_SCOPE_REGEX;
import static org.springframework.util.StringUtils.hasText;

@Controller
public class ScimGroupEndpoints {

    public static final String E_TAG = "ETag";

    private final ScimGroupProvisioning dao;

    private ScimGroupMembershipManager membershipManager;

    private JdbcScimGroupExternalMembershipManager externalMembershipManager;

    private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<>();

    private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
        new HttpMessageConverter<?>[0]);

    private final Log logger = LogFactory.getLog(getClass());

    private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

    public void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
        this.securityContextAccessor = securityContextAccessor;
    }

    public void setStatuses(Map<Class<? extends Exception>, HttpStatus> statuses) {
        this.statuses = statuses;
    }

    public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
        this.messageConverters = messageConverters;
    }

    public JdbcScimGroupExternalMembershipManager getExternalMembershipManager() {
        return externalMembershipManager;
    }

    public void setExternalMembershipManager(JdbcScimGroupExternalMembershipManager externalMembershipManager) {
        this.externalMembershipManager = externalMembershipManager;
    }

    public ScimGroupEndpoints(ScimGroupProvisioning scimGroupProvisioning, ScimGroupMembershipManager membershipManager) {
        this.dao = scimGroupProvisioning;
        this.membershipManager = membershipManager;
    }

    private boolean isMember(ScimGroup group, String userId, ScimGroupMember.Role role) {
        if (null == userId) {
            return true;
        }
        for (ScimGroupMember member : group.getMembers()) {
            if (member.getMemberId().equals(userId) && member.getRoles().contains(role)) {
                return true;
            }
        }
        return false;
    }

    private List<ScimGroup> filterForCurrentUser(List<ScimGroup> input, int startIndex, int count) {
        List<ScimGroup> response = new ArrayList<ScimGroup>();
        int expectedResponseSize = Math.min(count, input.size());
        boolean needMore = response.size() < expectedResponseSize;
        while (needMore && startIndex <= input.size()) {
            for (ScimGroup group : UaaPagingUtils.subList(input, startIndex, count)) {
                group.setMembers(membershipManager.getMembers(group.getId(), null, false));
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

    @RequestMapping(value = { "/Groups" }, method = RequestMethod.GET)
    @ResponseBody
    public SearchResults<?> listGroups(
        @RequestParam(value = "attributes", required = false) String attributesCommaSeparated,
        @RequestParam(required = false, defaultValue = "id pr") String filter,
        @RequestParam(required = false, defaultValue = "created") String sortBy,
        @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
        @RequestParam(required = false, defaultValue = "1") int startIndex,
        @RequestParam(required = false, defaultValue = "100") int count) {

        List<ScimGroup> result;
        try {
            result = dao.query(filter, sortBy, "ascending".equalsIgnoreCase(sortOrder));
        } catch (IllegalArgumentException e) {
            throw new ScimException("Invalid filter expression: [" + filter + "]", HttpStatus.BAD_REQUEST);
        }

        List<ScimGroup> input = filterForCurrentUser(result, startIndex, count);

        if (!StringUtils.hasLength(attributesCommaSeparated)) {
            return new SearchResults<>(Arrays.asList(ScimCore.SCHEMAS), input, startIndex, count,
                                       result.size());
        }

        AttributeNameMapper mapper = new SimpleAttributeNameMapper(Collections.emptyMap());

        String[] attributes = attributesCommaSeparated.split(",");
        try {
            return SearchResultsFactory.buildSearchResultFrom(input, startIndex, count, result.size(), attributes,
                                                              mapper,Arrays.asList(ScimCore.SCHEMAS));
        } catch (JsonPathException e) {
            throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
        }
    }

    @RequestMapping(value = { "/Groups/External/list" }, method = RequestMethod.GET)
    @ResponseBody
    @Deprecated
    public SearchResults<?> listExternalGroups(
        @RequestParam(required = false, defaultValue = "1") int startIndex,
        @RequestParam(required = false, defaultValue = "100") int count,
        @RequestParam(required = false, defaultValue = "") String filter) {
        return getExternalGroups(startIndex, count, filter);
    }

    @RequestMapping(value = { "/Groups/External" }, method = RequestMethod.GET)
    @ResponseBody
    public SearchResults<?> getExternalGroups(
        @RequestParam(required = false, defaultValue = "1") int startIndex,
        @RequestParam(required = false, defaultValue = "100") int count,
        @RequestParam(required = false, defaultValue = "") String filter) {

        List<ScimGroupExternalMember> result;
        try {

            result = externalMembershipManager.query(filter);
        } catch (IllegalArgumentException e) {
            throw new ScimException("Invalid filter expression: [" + filter + "]", e, HttpStatus.BAD_REQUEST);
        }
        return SearchResultsFactory.cropAndBuildSearchResultFrom(
            result,
            startIndex,
            count,
            result.size(),
            new String[]{"groupId", "displayName", "externalGroup", "origin"},
            Arrays.asList(ScimCore.SCHEMAS));
    }

    @RequestMapping(value = { "/Groups/External" }, method = RequestMethod.POST)
    @ResponseBody
    @ResponseStatus(HttpStatus.CREATED)
    public ScimGroupExternalMember mapExternalGroup(@RequestBody ScimGroupExternalMember sgm) {
        try {
            String displayName = sgm.getDisplayName();
            String groupId = hasText(sgm.getGroupId()) ? sgm.getGroupId() : getGroupId(displayName);
            String externalGroup = hasText(sgm.getExternalGroup()) ? sgm.getExternalGroup().trim() : sgm.getExternalGroup();
            String origin = hasText(sgm.getOrigin()) ? sgm.getOrigin() : LDAP;
            return externalMembershipManager.mapExternalGroup(groupId, externalGroup, origin);
        } catch (IllegalArgumentException e) {
            throw new ScimException(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (ScimResourceNotFoundException e) {
            throw new ScimException(e.getMessage(), HttpStatus.NOT_FOUND);
        } catch (MemberAlreadyExistsException e) {
            throw new ScimException(e.getMessage(), HttpStatus.CONFLICT);
        }
    }

    @RequestMapping(value = { "/Groups/External/groupId/{groupId}/externalGroup/{externalGroup}" }, method = RequestMethod.DELETE)
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    @Deprecated
    public ScimGroupExternalMember deprecated2UnmapExternalGroup(@PathVariable String groupId, @PathVariable String externalGroup) {
        return unmapExternalGroup(groupId, externalGroup, null);
    }

    @RequestMapping(value = { "/Groups/External/groupId/{groupId}/externalGroup/{externalGroup}/origin/{origin}" }, method = RequestMethod.DELETE)
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    public ScimGroupExternalMember unmapExternalGroup(@PathVariable String groupId,
                                                      @PathVariable String externalGroup,
                                                      @PathVariable String origin) {
        try {
            if (!hasText(origin)) {
                origin = LDAP;
            }
            return externalMembershipManager.unmapExternalGroup(groupId, externalGroup.trim(), origin);
        } catch (IllegalArgumentException e) {
            throw new ScimException(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (ScimResourceNotFoundException e) {
            throw new ScimException(e.getMessage(), HttpStatus.NOT_FOUND);
        } catch (MemberAlreadyExistsException e) {
            throw new ScimException(e.getMessage(), HttpStatus.CONFLICT);
        }
    }

    @RequestMapping(value = { "/Groups/External/id/{groupId}/{externalGroup}" }, method = RequestMethod.DELETE)
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    @Deprecated
    public ScimGroupExternalMember deprecatedUnmapExternalGroup(@PathVariable String groupId, @PathVariable String externalGroup) {
        return unmapExternalGroup(groupId, externalGroup, LDAP);
    }

    @RequestMapping(value = { "/Groups/External/displayName/{displayName}/externalGroup/{externalGroup}" }, method = RequestMethod.DELETE)
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    @Deprecated
    public ScimGroupExternalMember unmapExternalGroupUsingName(@PathVariable String displayName, @PathVariable String externalGroup) {
        return unmapExternalGroupUsingName(displayName, externalGroup, LDAP);
    }

    @RequestMapping(value = { "/Groups/External/displayName/{displayName}/externalGroup/{externalGroup}/origin/{origin}" }, method = RequestMethod.DELETE)
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    public ScimGroupExternalMember unmapExternalGroupUsingName(@PathVariable String displayName,
                                                               @PathVariable String externalGroup,
                                                               @PathVariable String origin) {
        try {
            if (!hasText(origin)) {
                origin = LDAP;
            }

            return externalMembershipManager.unmapExternalGroup(getGroupId(displayName), externalGroup.trim(),origin);
        } catch (IllegalArgumentException e) {
            throw new ScimException(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (ScimResourceNotFoundException e) {
            throw new ScimException(e.getMessage(), HttpStatus.NOT_FOUND);
        } catch (MemberAlreadyExistsException e) {
            throw new ScimException(e.getMessage(), HttpStatus.CONFLICT);
        }
    }

    @RequestMapping(value = { "/Groups/External/{displayName}/{externalGroup}" }, method = RequestMethod.DELETE)
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    @Deprecated
    public ScimGroupExternalMember deprecatedUnmapExternalGroupUsingName(@PathVariable String displayName, @PathVariable String externalGroup) {
        return unmapExternalGroupUsingName(displayName, externalGroup);
    }

    private String getGroupId(String displayName) {
        if (displayName==null || displayName.trim().length()==0) {
            throw new ScimException("Group not found, not name provided", HttpStatus.NOT_FOUND);
        }
        List<ScimGroup> result = dao.query("displayName eq \""+displayName+"\"");
        if (result==null || result.size()==0) {
            throw new ScimException("Group not found:"+displayName, HttpStatus.NOT_FOUND);
        }
        return result.get(0).getId();
    }


    @RequestMapping(value = { "/Groups/{groupId}" }, method = RequestMethod.GET)
    @ResponseBody
    public ScimGroup getGroup(@PathVariable String groupId, HttpServletResponse httpServletResponse) {
        logger.debug("retrieving group with id: " + groupId);
        ScimGroup group = dao.retrieve(groupId);
        group.setMembers(membershipManager.getMembers(groupId, null, false));
        addETagHeader(httpServletResponse, group);
        return group;
    }

    @RequestMapping(value = { "/Groups" }, method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public ScimGroup createGroup(@RequestBody ScimGroup group, HttpServletResponse httpServletResponse) {
        group.setZoneId(IdentityZoneHolder.get().getId());
        ScimGroup created = dao.create(group);
        if (group.getMembers() != null) {
            for (ScimGroupMember member : group.getMembers()) {
                try {
                    membershipManager.addMember(created.getId(), member);
                } catch (ScimException ex) {
                    logger.warn("Attempt to add invalid member: " + member.getMemberId() + " to group: " + created.getId(), ex);
                    dao.delete(created.getId(), created.getVersion());
                    throw new InvalidScimResourceException("Invalid group member: " + member.getMemberId());
                }
            }
        }
        created.setMembers(membershipManager.getMembers(created.getId(), null, false));
        addETagHeader(httpServletResponse, created);
        return created;
    }

    @RequestMapping(value = { "/Groups/{groupId}" }, method = RequestMethod.PUT)
    @ResponseBody
    public ScimGroup updateGroup(@RequestBody ScimGroup group, @PathVariable String groupId,
                                 @RequestHeader(value = "If-Match", required = false) String etag,
                                 HttpServletResponse httpServletResponse) {
        if (etag == null) {
            throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
        }
        logger.debug("updating group: " + groupId);
        int version = getVersion(groupId, etag);
        group.setVersion(version);
        ScimGroup existing = getGroup(groupId, httpServletResponse);
        try {
            group.setZoneId(IdentityZoneHolder.get().getId());
            ScimGroup updated = dao.update(groupId, group);
            if (group.getMembers() != null && group.getMembers().size() > 0) {
                membershipManager.updateOrAddMembers(updated.getId(), group.getMembers());
            } else {
                membershipManager.removeMembersByGroupId(updated.getId());
            }
            updated.setMembers(membershipManager.getMembers(updated.getId(), null, false));
            addETagHeader(httpServletResponse, updated);
            return updated;
        } catch (IncorrectResultSizeDataAccessException ex) {
            logger.error("Error updating group, restoring to previous state");
            // restore to correct state before reporting error
            existing.setVersion(getVersion(groupId, "*"));
            dao.update(groupId, existing);
            throw new ScimException(ex.getMessage(), ex, HttpStatus.CONFLICT);
        } catch (ScimResourceNotFoundException ex) {
            logger.error("Error updating group, restoring to previous state: " + existing);
            // restore to correct state before reporting error
            existing.setVersion(getVersion(groupId, "*"));
            dao.update(groupId, existing);
            throw new ScimException(ex.getMessage(), ex, HttpStatus.BAD_REQUEST);
        }
    }

    @RequestMapping(value = { "/Groups/{groupId}" }, method = RequestMethod.PATCH)
    @ResponseBody
    public ScimGroup patchGroup(@RequestBody ScimGroup patch, @PathVariable
                                String groupId,
                                @RequestHeader(value = "If-Match", required = false) String etag,
                                HttpServletResponse httpServletResponse) {
        if (etag == null) {
            throw new ScimException("Missing If-Match for PATCH", HttpStatus.BAD_REQUEST);
        }
        logger.debug("patching group: " + groupId);
        int version = getVersion(groupId, etag);
        patch.setVersion(version);
        ScimGroup current = getGroup(groupId, httpServletResponse);
        current.patch(patch);
        return updateGroup(current, groupId, etag, httpServletResponse);
    }

    @RequestMapping(value = { "/Groups/{groupId}" }, method = RequestMethod.DELETE)
    @ResponseBody
    public ScimGroup deleteGroup(@PathVariable String groupId,
                                 @RequestHeader(value = "If-Match", required = false, defaultValue = "*") String etag,
                                 HttpServletResponse httpServletResponse) {
        ScimGroup group = getGroup(groupId, httpServletResponse);
        logger.debug("deleting group: " + group);
        try {
            membershipManager.removeMembersByGroupId(groupId);
            membershipManager.removeMembersByMemberId(groupId);
            dao.delete(groupId, getVersion(groupId, etag));
        } catch (IncorrectResultSizeDataAccessException ex) {
            logger.debug("error deleting group", ex);
            throw new ScimException("error deleting group: " + groupId, ex, HttpStatus.CONFLICT);
        }
        return group;
    }

    @RequestMapping(value = { "/Groups/zones" }, method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    @Deprecated
    public ScimGroup addZoneManagers(@RequestBody ScimGroup group, HttpServletResponse httpServletResponse) {
        if (!group.getDisplayName().matches(ZONE_MANAGING_SCOPE_REGEX)) {
            throw new ScimException("Invalid group name.", HttpStatus.BAD_REQUEST);
        }
        if (group.getMembers()==null || group.getMembers().size()==0) {
            throw new ScimException("Invalid group members, you have to add at least one member.", HttpStatus.BAD_REQUEST);
        }
        try {
            ScimGroup existing = getGroup(getGroupId(group.getDisplayName()),httpServletResponse);
            List<ScimGroupMember> newMembers = new LinkedList<>(existing.getMembers());
            //we have an existing group - add new memberships
            for (ScimGroupMember member : group.getMembers()) {
                if (!isMember(existing, member.getMemberId(), ScimGroupMember.Role.MEMBER)) {
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

    @RequestMapping(value = { "/Groups/zones/{userId}/{zoneId}" }, method = RequestMethod.DELETE)
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    @Deprecated
    public ScimGroup deleteZoneAdmin(@PathVariable String userId, @PathVariable String zoneId, HttpServletResponse httpServletResponse) {
        return deleteZoneScope(userId, zoneId, "admin", httpServletResponse);
    }

    @RequestMapping(value = { "/Groups/zones/{userId}/{zoneId}/{scope}" }, method = RequestMethod.DELETE)
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    @Deprecated
    public ScimGroup deleteZoneScope(@PathVariable String userId,
                                     @PathVariable String zoneId,
                                     @PathVariable String scope,
                                     HttpServletResponse httpServletResponse) {

        String groupName = "zones."+zoneId+"."+scope;
        if (!groupName.matches(ZONE_MANAGING_SCOPE_REGEX)) {
            throw new ScimException("Invalid group name.", HttpStatus.BAD_REQUEST);
        }
        String groupId = getGroupId(groupName);
        ScimGroup group = getGroup(groupId, httpServletResponse);
        if (!hasText(userId) || !hasText(zoneId)) {
            throw new ScimException("User ID and Zone ID are required.", HttpStatus.BAD_REQUEST);
        }
        if (!isMember(group, userId, ScimGroupMember.Role.MEMBER)) {
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

    @RequestMapping("/Groups/{groupId}/members/{memberId}")
    public ResponseEntity<ScimGroupMember> getGroupMembership(@PathVariable String groupId, @PathVariable String memberId) {
        ScimGroupMember membership = membershipManager.getMemberById(groupId, memberId);
        return new ResponseEntity<>(membership, HttpStatus.OK);
    }

    @RequestMapping("/Groups/{groupId}/members")
    public ResponseEntity<List<ScimGroupMember>> listGroupMemberships(@PathVariable String groupId,
          @RequestParam(required = false, defaultValue = "false") boolean returnEntities,
          @RequestParam(required = false, defaultValue = "") String filter) {
        dao.retrieve(groupId);
        List<ScimGroupMember> members = membershipManager.getMembers(groupId, filter, returnEntities);
        return new ResponseEntity<>(members, HttpStatus.OK);
    }

    @RequestMapping(value = "/Groups/{groupId}/members", method = RequestMethod.PUT)
    @ResponseBody
    @Deprecated
    public ScimGroupMember editMemberInGroup(@PathVariable String groupId, @RequestBody ScimGroupMember member) {
        return membershipManager.updateMember(groupId, member);
    }

    @RequestMapping(value = "/Groups/{groupId}/members", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public ScimGroupMember addMemberToGroup(@PathVariable String groupId, @RequestBody ScimGroupMember member) {

        return membershipManager.addMember(groupId, member);
    }
    @RequestMapping(value = "/Groups/{groupId}/members/{memberId}", method = RequestMethod.DELETE)
    @ResponseBody
    @ResponseStatus(HttpStatus.OK)
    public ScimGroupMember deleteGroupMembership(@PathVariable String groupId, @PathVariable String memberId) {
        ScimGroupMember membership = membershipManager.removeMemberById(groupId, memberId);
        return membership;
    }

    @ExceptionHandler
    public View handleException(Exception t, HttpServletRequest request) throws ScimException {
        ScimException e = new ScimException("Unexpected error", t, HttpStatus.INTERNAL_SERVER_ERROR);
        if (t instanceof ScimException) {
            e = (ScimException) t;
        } else {
            Class<?> clazz = t.getClass();
            for (Class<?> key : statuses.keySet()) {
                if (key.isAssignableFrom(clazz)) {
                    e = new ScimException(t.getMessage(), t, statuses.get(key));
                    break;
                }
            }
        }
        // User can supply trace=true or just trace (unspecified) to get stack
        // traces
        boolean trace = request.getParameter("trace") != null && !request.getParameter("trace").equals("false");
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
        if (value.equals("*")) {
            return dao.retrieve(groupId).getVersion();
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
