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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.account.event.UserAccountUnlockedEvent;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.mfa.UserMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.*;
import org.cloudfoundry.identity.uaa.scim.*;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConflictException;
import org.cloudfoundry.identity.uaa.scim.exception.UserAlreadyVerifiedException;
import org.cloudfoundry.identity.uaa.scim.util.ScimUtils;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.security.ScimUserUpdateDiff;
import org.cloudfoundry.identity.uaa.util.DomainFilter;
import org.cloudfoundry.identity.uaa.util.UaaPagingUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2ExpressionUtils;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.REGISTRATION;
import static org.springframework.util.StringUtils.isEmpty;

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
@ManagedResource(
    objectName="cloudfoundry.identity:name=UserEndpoint",
    description = "UAA User API Metrics"
)
public class ScimUserEndpoints implements InitializingBean, ApplicationEventPublisherAware {
    private static final String USER_APPROVALS_FILTER_TEMPLATE = "user_id eq \"%s\"";

    private static Logger logger = LoggerFactory.getLogger(ScimUserEndpoints.class);

    public static final String E_TAG = "ETag";

    private ScimUserProvisioning scimUserProvisioning;

    private IdentityProviderProvisioning identityProviderProvisioning;

    private ResourceMonitor<ScimUser> scimUserResourceMonitor;

    private ScimGroupMembershipManager membershipManager;

    private UserMfaCredentialsProvisioning mfaCredentialsProvisioning;

    private ApprovalStore approvalStore;

    private static final Random passwordGenerator = new SecureRandom();

    private final Map<String, AtomicInteger> errorCounts = new ConcurrentHashMap<String, AtomicInteger>();

    private AtomicInteger scimUpdates = new AtomicInteger();

    private AtomicInteger scimDeletes = new AtomicInteger();

    private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();

    private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
                    new HttpMessageConverter<?>[0]);

    private PasswordValidator passwordValidator;

    private ExpiringCodeStore codeStore;

    private ApplicationEventPublisher publisher;

    private int userMaxCount;

    private IsSelfCheck isSelfCheck;

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Total Users")
    public int getTotalUsers() {
        return scimUserResourceMonitor.getTotalCount();
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
    public ScimUser getUser(@PathVariable String userId, HttpServletResponse response) {
        ScimUser scimUser = syncApprovals(syncGroups(scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId())));
        addETagHeader(response, scimUser);
        return scimUser;
    }

    @RequestMapping(value = "/Users", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public ScimUser createUser(@RequestBody ScimUser user, HttpServletRequest request, HttpServletResponse response) {
        //default to UAA origin
        if (isEmpty(user.getOrigin())) {
            user.setOrigin(OriginKeys.UAA);
        }

        throwWhenUserManagementIsDisallowed(user.getOrigin(), request);
        ScimUtils.validate(user);
        if (!isUaaUser(user)) {
            //set a default password, "" for non UAA users.
            user.setPassword("");
        } else {
            //only validate for UAA users
            List<IdentityProvider> idpsForEmailDomain = DomainFilter.getIdpsForEmailDomain(identityProviderProvisioning.retrieveActive(IdentityZoneHolder.get().getId()), user.getEmails().get(0).getValue());
            idpsForEmailDomain = idpsForEmailDomain.stream().filter(idp -> !idp.getOriginKey().equals(OriginKeys.UAA)).collect(Collectors.toList());
            if(!idpsForEmailDomain.isEmpty()) {
                List<String> idpOrigins = idpsForEmailDomain.stream().map(idp -> idp.getOriginKey()).collect(Collectors.toList());
                throw new ScimException(String.format("The user account is set up for single sign-on. Please use one of these origin(s) : %s",idpOrigins.toString()), HttpStatus.BAD_REQUEST);
            }
            passwordValidator.validate(user.getPassword());
        }

        ScimUser scimUser = scimUserProvisioning.createUser(user, user.getPassword(), IdentityZoneHolder.get().getId());
        if (user.getApprovals()!=null) {
            for (Approval approval : user.getApprovals()) {
                approval.setUserId(scimUser.getId());
                approvalStore.addApproval(approval, IdentityZoneHolder.get().getId());
            }
        }
        scimUser = syncApprovals(syncGroups(scimUser));
        addETagHeader(response, scimUser);
        return scimUser;
    }

    public boolean isUaaUser(@RequestBody ScimUser user) {
        return OriginKeys.UAA.equals(user.getOrigin());
    }

    @RequestMapping(value = "/Users/{userId}", method = RequestMethod.PUT)
    @ResponseBody
    public ScimUser updateUser(@RequestBody ScimUser user, @PathVariable String userId,
                               @RequestHeader(value = "If-Match", required = false, defaultValue = "NaN") String etag,
                               HttpServletRequest request,
                               HttpServletResponse httpServletResponse,
                               OAuth2Authentication authentication) {

        throwWhenUserManagementIsDisallowed(user.getOrigin(), request);
        throwWhenInvalidSelfEdit(user, userId, request, authentication);

        if (etag.equals("NaN")) {
            throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
        }
        int version = getVersion(userId, etag);
        user.setVersion(version);

        try {
            ScimUser updated = scimUserProvisioning.update(userId, user, IdentityZoneHolder.get().getId());
            scimUpdates.incrementAndGet();
            ScimUser scimUser = syncApprovals(syncGroups(updated));
            addETagHeader(httpServletResponse, scimUser);
            return scimUser;
        } catch (OptimisticLockingFailureException e) {
            throw new ScimResourceConflictException(e.getMessage());
        }
    }

    @RequestMapping(value = "/Users/{userId}", method = RequestMethod.PATCH)
    @ResponseBody
    public ScimUser patchUser(@RequestBody ScimUser patch, @PathVariable String userId,
                              @RequestHeader(value = "If-Match", required = false, defaultValue = "NaN") String etag,
                              HttpServletRequest request,
                              HttpServletResponse response,
                              OAuth2Authentication authentication) {

        if (etag.equals("NaN")) {
            throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
        }

        int version = getVersion(userId, etag);
        ScimUser existing = scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId());
        try {
            existing.patch(patch);
            existing.setVersion(version);
            if (existing.getEmails()!=null && existing.getEmails().size()>1) {
                String primary = existing.getPrimaryEmail();
                existing.setEmails(new ArrayList<>());
                existing.setPrimaryEmail(primary);
            }
            return updateUser(existing, userId, etag, request, response, authentication);
        } catch (IllegalArgumentException x) {
            throw new InvalidScimResourceException(x.getMessage());
        }
    }

    @RequestMapping(value = "/Users/{userId}", method = RequestMethod.DELETE)
    @ResponseBody
    public ScimUser deleteUser(@PathVariable String userId,
                               @RequestHeader(value = "If-Match", required = false) String etag,
                               HttpServletRequest request,
                               HttpServletResponse httpServletResponse) {
        int version = etag == null ? -1 : getVersion(userId, etag);
        ScimUser user = getUser(userId, httpServletResponse);
        throwWhenUserManagementIsDisallowed(user.getOrigin(), request);
        membershipManager.removeMembersByMemberId(userId, user.getOrigin(), IdentityZoneHolder.get().getId());
        scimUserProvisioning.delete(userId, version, IdentityZoneHolder.get().getId());
        scimDeletes.incrementAndGet();
        if (publisher != null) {
            publisher.publishEvent(
                new EntityDeletedEvent<>(
                    user,
                    SecurityContextHolder.getContext().getAuthentication(),
                        IdentityZoneHolder.getCurrentZoneId())
            );
            logger.debug("User delete event sent[" + userId + "]");
        }
        return user;
    }

    @RequestMapping(value = "/Users/{userId}/verify-link", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity<VerificationResponse> getUserVerificationLink(@PathVariable String userId,
                                @RequestParam(value="client_id", required = false) String clientId,
                                @RequestParam(value="redirect_uri") String redirectUri) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2Authentication) {
            OAuth2Authentication oAuth2Authentication = (OAuth2Authentication)authentication;

            if (clientId==null) {
                clientId = oAuth2Authentication.getOAuth2Request().getClientId();
            }
        }

        VerificationResponse responseBody = new VerificationResponse();

        ScimUser user = scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId());
        if (user.isVerified()) {
            throw new UserAlreadyVerifiedException();
        }

        ExpiringCode expiringCode = ScimUtils.getExpiringCode(codeStore, userId, user.getPrimaryEmail(), clientId, redirectUri, REGISTRATION, IdentityZoneHolder.getCurrentZoneId());
        responseBody.setVerifyLink(ScimUtils.getVerificationURL(expiringCode, IdentityZoneHolder.get()));

        return new ResponseEntity<>(responseBody, HttpStatus.OK);
    }

    @RequestMapping(value = "/Users/{userId}/verify", method = RequestMethod.GET)
    @ResponseBody
    public ScimUser verifyUser(@PathVariable String userId,
                    @RequestHeader(value = "If-Match", required = false) String etag,
                    HttpServletResponse httpServletResponse) {
        int version = etag == null ? -1 : getVersion(userId, etag);
        ScimUser user = scimUserProvisioning.verifyUser(userId, version, IdentityZoneHolder.get().getId());
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
            return scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId()).getVersion();
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
                    @RequestParam(required = false, defaultValue = "created") String sortBy,
                    @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
                    @RequestParam(required = false, defaultValue = "1") int startIndex,
                    @RequestParam(required = false, defaultValue = "100") int count) {

        if (startIndex < 1) {
            startIndex = 1;
        }

        if (count > userMaxCount) {
            count = userMaxCount;
        }

        List<ScimUser> input = new ArrayList<ScimUser>();
        List<ScimUser> result;
        Set<String> attributes = StringUtils.commaDelimitedListToSet(attributesCommaSeparated);
        try {
            result = scimUserProvisioning.query(filter, sortBy, sortOrder.equals("ascending"), IdentityZoneHolder.get().getId());
            for (ScimUser user : UaaPagingUtils.subList(result, startIndex, count)) {
                if(attributes.isEmpty() || attributes.stream().anyMatch(p -> "groups".equalsIgnoreCase(p))) {
                    syncGroups(user);
                }
                if(attributes.isEmpty() || attributes.stream().anyMatch(p -> "approvals".equalsIgnoreCase(p))) {
                    syncApprovals(user);
                }
                input.add(user);
            }
        } catch (IllegalArgumentException e) {
            String msg = "Invalid filter expression: [" + filter + "]";
            if (StringUtils.hasText(sortBy)) {
                msg += " [" +sortBy+"]";
            }
            throw new ScimException(msg, HttpStatus.BAD_REQUEST);
        }

        if (!StringUtils.hasLength(attributesCommaSeparated)) {
            // Return all user data
            return new SearchResults<>(Arrays.asList(ScimCore.SCHEMAS), input, startIndex, count, result.size());
        }

        Map<String, String> attributeMap = new HashMap<>();
        attributeMap.put("^emails\\.", "emails[*].");
        attributeMap.put("familyName", "name.familyName");
        attributeMap.put("givenName", "name.givenName");
        AttributeNameMapper mapper = new SimpleAttributeNameMapper(attributeMap);

        try {
            return SearchResultsFactory.buildSearchResultFrom(input,
                                                              startIndex,
                                                              count,
                                                              result.size(),
                                                              attributes.toArray(new String[attributes.size()]),
                                                              mapper,
                                                              Arrays.asList(ScimCore.SCHEMAS)
            );
        } catch (JsonPathException e) {
            throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
        }
    }

    @RequestMapping(value = "/Users/{userId}/status", method = RequestMethod.PATCH)
    public UserAccountStatus updateAccountStatus(@RequestBody UserAccountStatus status, @PathVariable String userId) {
        ScimUser user = scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId());

        if(!user.getOrigin().equals(OriginKeys.UAA)) {
            throw new IllegalArgumentException("Can only manage users from the internal user store.");
        }
        if(status.getLocked() != null && status.getLocked()) {
            throw new IllegalArgumentException("Cannot set user account to locked. User accounts only become locked through exceeding the allowed failed login attempts.");
        }
        if(status.getPasswordChangeRequired() != null && !status.getPasswordChangeRequired()) {
            throw new IllegalArgumentException("The requirement that this user change their password cannot be removed via API.");
        }


        if(status.getLocked() != null && !status.getLocked()) {
            publish(new UserAccountUnlockedEvent(user, IdentityZoneHolder.getCurrentZoneId()));
        }
        if(status.getPasswordChangeRequired() != null && status.getPasswordChangeRequired()) {
            scimUserProvisioning.updatePasswordChangeRequired(userId, true, IdentityZoneHolder.get().getId());
        }

        return status;
    }

    @RequestMapping(value = "/Users/{userId}/mfa", method = RequestMethod.DELETE)
    @ResponseStatus(HttpStatus.OK)
    public void deleteMfaRegistration(@PathVariable String userId) {
        ScimUser user = scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId());

        mfaCredentialsProvisioning.delete(user.getId());
    }

    protected ScimUser syncGroups(ScimUser user) {
        if (user == null) {
            return user;
        }

        Set<ScimGroup> directGroups = membershipManager.getGroupsWithMember(user.getId(), false, IdentityZoneHolder.get().getId());
        Set<ScimGroup> indirectGroups = membershipManager.getGroupsWithMember(user.getId(), true, IdentityZoneHolder.get().getId());
        indirectGroups.removeAll(directGroups);
        Set<ScimUser.Group> groups = new HashSet<ScimUser.Group>();
        for (ScimGroup group : directGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.DIRECT));
        }
        for (ScimGroup group : indirectGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.INDIRECT));
        }

        user.setGroups(groups);
        return user;
    }

    protected ScimUser syncApprovals(ScimUser user) {
        if (user == null || approvalStore == null) {
            return user;
        }
        Set<Approval> approvals = new HashSet<Approval>(approvalStore.getApprovalsForUser(user.getId(), IdentityZoneHolder.get().getId()));
        Set<Approval> active = new HashSet<Approval>(approvals);
        for (Approval approval : approvals) {
            if (!approval.isActiveAsOf(new Date())) {
                active.remove(approval);
            }
        }
        user.setApprovals(active);
        return user;
    }

    @ExceptionHandler(UaaException.class)
    public ResponseEntity<UaaException> handleException(UaaException e) {
        logger.info("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
        if (e instanceof InternalUserManagementDisabledException) {
            throw e;
        }
        return new ResponseEntity<>(e, HttpStatus.valueOf(e.getHttpStatus()));
    }

    @ExceptionHandler
    public View handleException(Exception t, HttpServletRequest request) throws ScimException, InternalUserManagementDisabledException {
        logger.error("Unhandled exception in SCIM user endpoints.",t);
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
        return new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(e, trace, e.getExtraInfo()),
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

    private void publish(ApplicationEvent event) {
        if(publisher != null) {
            publisher.publishEvent(event);
        }
    }

    public void setScimUserProvisioning(ScimUserProvisioning dao) {
        this.scimUserProvisioning = dao;
    }

    public void setIdentityProviderProvisioning(IdentityProviderProvisioning identityProviderProvisioning) {
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    public void setScimGroupMembershipManager(ScimGroupMembershipManager membershipManager) {
        this.membershipManager = membershipManager;
    }

    public void setApprovalStore(ApprovalStore approvalStore) {
        this.approvalStore = approvalStore;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(scimUserProvisioning, "ScimUserProvisioning must be set");
        Assert.notNull(membershipManager, "ScimGroupMembershipManager must be set");
        Assert.notNull(approvalStore, "ApprovalStore must be set");
    }

    private void addETagHeader(HttpServletResponse httpServletResponse, ScimUser scimUser) {
        httpServletResponse.setHeader(E_TAG, "\"" + scimUser.getVersion() + "\"");
    }

    public void setScimUserResourceMonitor(ResourceMonitor<ScimUser> scimUserResourceMonitor) {
        this.scimUserResourceMonitor = scimUserResourceMonitor;
    }

    public void setPasswordValidator(PasswordValidator passwordValidator) {
        this.passwordValidator = passwordValidator;
    }

    public void setMfaCredentialsProvisioning(UserMfaCredentialsProvisioning mfaCredentialsProvisioning) {
        this.mfaCredentialsProvisioning = mfaCredentialsProvisioning;
    }

    public void setCodeStore(ExpiringCodeStore codeStore) {
        this.codeStore = codeStore;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public void setUserMaxCount(int userMaxCount) {
        if (userMaxCount <= 0) {
            throw new IllegalArgumentException(
                String.format("Invalid \"userMaxCount\" value (got %d). Should be positive number.", userMaxCount)
            );
        }

        this.userMaxCount = userMaxCount;
    }

    private void throwWhenUserManagementIsDisallowed(String origin, HttpServletRequest request) {
        Object attr = request.getAttribute(DisableInternalUserManagementFilter.DISABLE_INTERNAL_USER_MANAGEMENT);
        if (attr!=null && attr instanceof Boolean) {
            boolean isUserManagementDisabled = (boolean)attr;
            if (isUserManagementDisabled && (OriginKeys.UAA.equals(origin) || isEmpty(origin))) {
                throw new InternalUserManagementDisabledException(DisableUserManagementSecurityFilter.INTERNAL_USER_CREATION_IS_CURRENTLY_DISABLED);
            }
        }
    }

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

    private void throwWhenInvalidSelfEdit(ScimUser user, String userId, HttpServletRequest request, Authentication authentication) {
        boolean isSelfEdit = isSelfCheck.isUserSelf(request, 1);
        if (!isSelfEdit) {
            return;
        }

        if (OAuth2ExpressionUtils.hasAnyScope(authentication, new String[]{"uaa.admin", "scim.write"})) {
            return;
        }

        ScimUserUpdateDiff diffEngine = new ScimUserUpdateDiff(scimUserProvisioning);
        boolean selfUpdateAllowed = diffEngine.isAnythingOtherThanNameDifferent(userId, user);
        if (!selfUpdateAllowed) {
            throw new InvalidSelfEditException();
        }
    }

    public IsSelfCheck getIsSelfCheck() {
        return isSelfCheck;
    }

    public void setIsSelfCheck(IsSelfCheck isSelfCheck) {
        this.isSelfCheck = isSelfCheck;
    }

    private class InvalidSelfEditException extends UaaException {
        InvalidSelfEditException() {
            super("invalid_self_edit",
                    "Users are only allowed to edit their own User settings when internal user storage is enabled, " +
                            "and in that case they may only edit the givenName and familyName.",
                    403
            );
        }
    }
}
