/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReport;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.oauth.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.rest.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.rest.SearchResults;
import org.cloudfoundry.identity.uaa.rest.SearchResultsFactory;
import org.cloudfoundry.identity.uaa.rest.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.domain.ScimCoreInterface;
import org.cloudfoundry.identity.uaa.scim.domain.ScimGroupInterface;
import org.cloudfoundry.identity.uaa.scim.domain.ScimUser;
import org.cloudfoundry.identity.uaa.scim.domain.ScimUserGroupInterface;
import org.cloudfoundry.identity.uaa.scim.domain.ScimUserInterface;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConflictException;
import org.cloudfoundry.identity.uaa.util.UaaPagingUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
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

/**
 * User provisioning and query endpoints. Implements the core API from the
 * Simple Cloud Identity Management (SCIM)
 * group. Exposes basic CRUD and query features for user accounts in a backend
 * database.
 *
 * @author Luke Taylor
 * @author Dave Syer
 *
 * @see <a href="http://www.simplecloud.info">SCIM specs</a>
 */
@Controller
@ManagedResource
public class ScimUserEndpoints implements InitializingBean {
    private static final String USER_APPROVALS_FILTER_TEMPLATE = "userName eq '%s'";
    public static final String E_TAG = "ETag";

    private ScimUserProvisioning dao;

    private ScimGroupMembershipManager membershipManager;

    private ApprovalStore approvalStore;

    private static final Random passwordGenerator = new SecureRandom();

    private final Map<String, AtomicInteger> errorCounts = new ConcurrentHashMap<String, AtomicInteger>();

    private AtomicInteger scimUpdates = new AtomicInteger();

    private AtomicInteger scimDeletes = new AtomicInteger();

    private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();

    private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
                    new HttpMessageConverter<?>[0]);

    /**
     * Set the message body converters to use.
     * <p>
     * These converters are used to convert from and to HTTP requests and
     * responses.
     */
    public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
        this.messageConverters = messageConverters;
    }

    /**
     * Map from exception type to Http status.
     *
     * @param statuses the statuses to set
     */
    public void setStatuses(Map<Class<? extends Exception>, HttpStatus> statuses) {
        this.statuses = statuses;
    }

    private static String generatePassword() {
        byte[] bytes = new byte[16];
        passwordGenerator.nextBytes(bytes);
        return new String(Hex.encode(bytes));
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Total Users")
    public int getTotalUsers() {
        return dao.retrieveAll().size();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "User Account Update Count (Since Startup)")
    public int getUserUpdates() {
        return scimUpdates.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "User Account Delete Count (Since Startup)")
    public int getUserDeletes() {
        return scimDeletes.get();
    }

    @ManagedMetric(displayName = "Error Counts")
    public Map<String, AtomicInteger> getErrorCounts() {
        return errorCounts;
    }

    @RequestMapping(value = "/Users/{userId}", method = RequestMethod.GET)
    @ResponseBody
    public ScimUserInterface getUser(@PathVariable String userId, HttpServletResponse httpServletResponse) {
        ScimUserInterface ScimUserInterface = syncApprovals(syncGroups(dao.retrieve(userId)));
        addETagHeader(httpServletResponse, ScimUserInterface);
        return ScimUserInterface;
    }

    @RequestMapping(value = "/Users", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public ScimUserInterface createUser(@RequestBody ScimUserInterface user, HttpServletResponse httpServletResponse) {
        ScimUserInterface ScimUserInterface = syncApprovals(syncGroups(dao.createUser(user,
                        user.getPassword() == null ? generatePassword() : user.getPassword())));
        addETagHeader(httpServletResponse, ScimUserInterface);
        return ScimUserInterface;
    }

    @RequestMapping(value = "/Users/{userId}", method = RequestMethod.PUT)
    @ResponseBody
    public ScimUserInterface updateUser(@RequestBody ScimUserInterface user, @PathVariable String userId,
                    @RequestHeader(value = "If-Match", required = false, defaultValue = "NaN") String etag,
                    HttpServletResponse httpServletResponse) {
        if (etag.equals("NaN")) {
            throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
        }
        int version = getVersion(userId, etag);
        user.setVersion(version);
        try {
            ScimUserInterface updated = dao.update(userId, user);
            scimUpdates.incrementAndGet();
            ScimUserInterface ScimUserInterface = syncApprovals(syncGroups(updated));
            addETagHeader(httpServletResponse, ScimUserInterface);
            return ScimUserInterface;
        } catch (OptimisticLockingFailureException e) {
            throw new ScimResourceConflictException(e.getMessage());
        }
    }

    @RequestMapping(value = "/Users/{userId}", method = RequestMethod.DELETE)
    @ResponseBody
    public ScimUserInterface deleteUser(@PathVariable String userId,
                    @RequestHeader(value = "If-Match", required = false) String etag,
                    HttpServletResponse httpServletResponse) {
        int version = etag == null ? -1 : getVersion(userId, etag);
        ScimUserInterface user = getUser(userId, httpServletResponse);
        dao.delete(userId, version);
        membershipManager.removeMembersByMemberId(userId);
        scimDeletes.incrementAndGet();
        return user;
    }

    @RequestMapping(value = "/Users/{userId}/verify", method = RequestMethod.GET)
    @ResponseBody
    public ScimUserInterface verifyUser(@PathVariable String userId,
                    @RequestHeader(value = "If-Match", required = false) String etag,
                    HttpServletResponse httpServletResponse) {
        int version = etag == null ? -1 : getVersion(userId, etag);
        ScimUserInterface user = dao.verifyUser(userId, version);
        scimUpdates.incrementAndGet();
        addETagHeader(httpServletResponse, user);
        return user;
    }

    private int getVersion(String userId, String etag) {
        String value = etag.trim();
        while (value.startsWith("\"")) {
            value = value.substring(1);
        }
        while (value.endsWith("\"")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.equals("*")) {
            return dao.retrieve(userId).getVersion();
        }
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException e) {
            throw new ScimException("Invalid version match header (should be a version number): " + etag,
                            HttpStatus.BAD_REQUEST);
        }
    }

    @RequestMapping(value = "/Users", method = RequestMethod.GET)
    @ResponseBody
    public SearchResults<?> findUsers(
                    @RequestParam(value = "attributes", required = false) String attributesCommaSeparated,
                    @RequestParam(required = false, defaultValue = "id pr") String filter,
                    @RequestParam(required = false) String sortBy,
                    @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
                    @RequestParam(required = false, defaultValue = "1") int startIndex,
                    @RequestParam(required = false, defaultValue = "100") int count) {

        if (startIndex < 1) {
            startIndex = 1;
        }

        List<ScimUserInterface> input = new ArrayList<ScimUserInterface>();
        List<ScimUserInterface> result;
        try {
            result = dao.query(filter, sortBy, sortOrder.equals("ascending"));
            for (ScimUserInterface user : UaaPagingUtils.subList(result, startIndex, count)) {
                syncApprovals(syncGroups(user));
                input.add(user);
            }
        } catch (IllegalArgumentException e) {
            throw new ScimException("Invalid filter expression: [" + filter + "]", HttpStatus.BAD_REQUEST);
        }

        if (!StringUtils.hasLength(attributesCommaSeparated)) {
            // Return all user data
            return new SearchResults<ScimUserInterface>(Arrays.asList(ScimCoreInterface.SCHEMAS), input, startIndex, count, result.size());
        }

        AttributeNameMapper mapper = new SimpleAttributeNameMapper(Collections.<String, String> singletonMap(
                        "emails\\.(.*)", "emails.![$1]"));
        String[] attributes = attributesCommaSeparated.split(",");
        try {
            return SearchResultsFactory.buildSearchResultFrom(input, startIndex, count, result.size(), attributes,
                            mapper, Arrays.asList(ScimCoreInterface.SCHEMAS));
        } catch (SpelParseException e) {
            throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
        } catch (SpelEvaluationException e) {
            throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
        }
    }

    private ScimUserInterface syncGroups(ScimUserInterface user) {
        if (user == null) {
            return user;
        }

        Set<ScimGroupInterface> directGroups = membershipManager.getGroupsWithMember(user.getId(), false);
        Set<ScimGroupInterface> indirectGroups = membershipManager.getGroupsWithMember(user.getId(), true);
        indirectGroups.removeAll(directGroups);
        Set<ScimUserGroupInterface> groups = new HashSet<ScimUserGroupInterface>();
        for (ScimGroupInterface group : directGroups) {
            ScimUserGroupInterface userGroup = group.getUserGroup();
            userGroup.setType(ScimUserGroupInterface.Type.DIRECT);
            groups.add(userGroup);
        }
        for (ScimGroupInterface group : indirectGroups) {
            ScimUserGroupInterface userGroup = group.getUserGroup();
            userGroup.setType(ScimUserGroupInterface.Type.INDIRECT);
            groups.add(userGroup);
        }

        user.setGroups(groups);
        return user;
    }

    private ScimUserInterface syncApprovals(ScimUserInterface user) {
        if (user == null || approvalStore == null) {
            return user;
        }
        Set<Approval> approvals = new HashSet<Approval>(approvalStore.getApprovals(String.format(
                        USER_APPROVALS_FILTER_TEMPLATE, user.getUserName())));
        Set<Approval> active = new HashSet<Approval>(approvals);
        for (Approval approval : approvals) {
            if (!approval.isCurrentlyActive()) {
                active.remove(approval);
            }
        }
        user.setApprovals(active);
        return user;
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
        incrementErrorCounts(e);
        // User can supply trace=true or just trace (unspecified) to get stack
        // traces
        boolean trace = request.getParameter("trace") != null && !request.getParameter("trace").equals("false");
        return new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(e, trace),
                        e.getStatus()), messageConverters);
    }

    private void incrementErrorCounts(ScimException e) {
        String series = UaaStringUtils.getErrorName(e);
        AtomicInteger value = errorCounts.get(series);
        if (value == null) {
            synchronized (errorCounts) {
                value = errorCounts.get(series);
                if (value == null) {
                    value = new AtomicInteger();
                    errorCounts.put(series, value);
                }
            }
        }
        value.incrementAndGet();
    }

    public void setScimUserProvisioning(ScimUserProvisioning dao) {
        this.dao = dao;
    }

    public void setScimGroupMembershipManager(ScimGroupMembershipManager membershipManager) {
        this.membershipManager = membershipManager;
    }

    public void setApprovalStore(ApprovalStore approvalStore) {
        this.approvalStore = approvalStore;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(dao, "ScimUserProvisioning must be set");
        Assert.notNull(membershipManager, "ScimGroupMembershipManager must be set");
        Assert.notNull(approvalStore, "ApprovalStore must be set");
    }

    private void addETagHeader(HttpServletResponse httpServletResponse, ScimUserInterface ScimUserInterface) {
        httpServletResponse.setHeader(E_TAG, "\"" + ScimUserInterface.getVersion() + "\"");
    }
}
