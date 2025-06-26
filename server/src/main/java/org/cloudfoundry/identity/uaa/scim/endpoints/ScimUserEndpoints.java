package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.jayway.jsonpath.JsonPathException;
import lombok.Getter;
import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.account.event.UserAccountUnlockedEvent;
import org.cloudfoundry.identity.uaa.alias.AliasPropertiesInvalidException;
import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2ExpressionUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.resources.SearchResultsFactory;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.scim.DisableInternalUserManagementFilter;
import org.cloudfoundry.identity.uaa.scim.DisableUserManagementSecurityFilter;
import org.cloudfoundry.identity.uaa.scim.InternalUserManagementDisabledException;
import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConflictException;
import org.cloudfoundry.identity.uaa.scim.exception.UserAlreadyVerifiedException;
import org.cloudfoundry.identity.uaa.scim.services.ScimUserService;
import org.cloudfoundry.identity.uaa.scim.util.ScimUtils;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.security.ScimUserUpdateDiff;
import org.cloudfoundry.identity.uaa.util.DomainFilter;
import org.cloudfoundry.identity.uaa.util.UaaPagingUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.web.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.View;
import org.springframework.web.util.HtmlUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.REGISTRATION;
import static org.springframework.util.StringUtils.hasLength;
import static org.springframework.util.StringUtils.hasText;

/**
 * User provisioning and query endpoints. Implements the core API from the
 * Simple Cloud Identity Management (SCIM)
 * group. Exposes basic CRUD and query features for user accounts in a backend
 * database.
 *
 * @see <a href="http://www.simplecloud.info">SCIM specs</a>
 */
@Controller
@ManagedResource(
        objectName = "cloudfoundry.identity:name=UserEndpoint",
        description = "UAA User API Metrics"
)
public class ScimUserEndpoints implements InitializingBean, ApplicationEventPublisherAware {

    private static final Logger logger = LoggerFactory.getLogger(ScimUserEndpoints.class);
    private static final String E_TAG = "ETag";

    private final IdentityZoneManager identityZoneManager;
    private final IsSelfCheck isSelfCheck;
    private final ScimUserProvisioning scimUserProvisioning;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final ResourceMonitor<ScimUser> scimUserResourceMonitor;
    private final Map<Class<? extends Exception>, HttpStatus> statuses;
    private final PasswordValidator passwordValidator;
    private final ExpiringCodeStore codeStore;
    private final ApprovalStore approvalStore;
    private final ScimGroupMembershipManager membershipManager;
    private final boolean aliasEntitiesEnabled;
    @Getter
    private final int userMaxCount;
    private final HttpMessageConverter<?>[] messageConverters;
    /**
     * Update operations performed on alias users are not considered.
     */
    private final AtomicInteger scimUpdates;
    /**
     * Deletion operations performed on alias users are not considered.
     */
    private final AtomicInteger scimDeletes;
    private final Map<String, AtomicInteger> errorCounts;
    private final ScimUserService scimUserService;
    private final ScimUserAliasHandler aliasHandler;
    private final TransactionTemplate transactionTemplate;

    private ApplicationEventPublisher publisher;

    /**
     * @param statuses Map from exception type to Http status
     */
    public ScimUserEndpoints(
            final IdentityZoneManager identityZoneManager,
            final IsSelfCheck isSelfCheck,
            final ScimUserProvisioning scimUserProvisioning,
            final IdentityProviderProvisioning identityProviderProvisioning,
            final @Qualifier("scimUserProvisioning") ResourceMonitor<ScimUser> scimUserResourceMonitor,
            final @Qualifier("exceptionToStatusMap") Map<Class<? extends Exception>, HttpStatus> statuses,
            final PasswordValidator passwordValidator,
            final ExpiringCodeStore codeStore,
            final ApprovalStore approvalStore,
            final ScimGroupMembershipManager membershipManager,
            final ScimUserService scimUserService,
            final ScimUserAliasHandler aliasHandler,
            final TransactionTemplate transactionTemplate,
            final @Qualifier("aliasEntitiesEnabled") boolean aliasEntitiesEnabled,
            final @Value("${userMaxCount:500}") int userMaxCount
    ) {
        if (userMaxCount <= 0) {
            throw new IllegalArgumentException(
                    "Invalid \"userMaxCount\" value (got %d). Should be positive number.".formatted(userMaxCount)
            );
        }

        this.identityZoneManager = identityZoneManager;
        this.isSelfCheck = isSelfCheck;
        this.scimUserProvisioning = scimUserProvisioning;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.scimUserResourceMonitor = scimUserResourceMonitor;
        this.statuses = statuses;
        this.passwordValidator = passwordValidator;
        this.codeStore = codeStore;
        this.approvalStore = approvalStore;
        this.aliasEntitiesEnabled = aliasEntitiesEnabled;
        this.userMaxCount = userMaxCount;
        this.membershipManager = membershipManager;
        this.messageConverters = new HttpMessageConverter[]{
                new ExceptionReportHttpMessageConverter()
        };
        this.scimUserService = scimUserService;
        this.aliasHandler = aliasHandler;
        this.transactionTemplate = transactionTemplate;
        scimUpdates = new AtomicInteger();
        scimDeletes = new AtomicInteger();
        errorCounts = new ConcurrentHashMap<>();
    }

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

    @GetMapping("/Users/{userId}")
    @ResponseBody
    public ScimUser getUser(@PathVariable String userId, HttpServletResponse response) {
        ScimUser scimUser = syncApprovals(syncGroups(scimUserProvisioning.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId())));
        addETagHeader(response, scimUser);
        return scimUser;
    }

    @PostMapping("/Users")
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public ScimUser createUser(@RequestBody ScimUser user, HttpServletRequest request, HttpServletResponse response) {
        //default to UAA origin
        if (!hasLength(user.getOrigin())) {
            user.setOrigin(OriginKeys.UAA);
        }

        throwWhenUserManagementIsDisallowed(user.getOrigin(), request);
        ScimUtils.validate(user);
        if (!isUaaUser(user)) {
            //set a default password, "" for non UAA users.
            user.setPassword("");
        } else {
            //only validate for UAA users
            List<IdentityProvider> idpsForEmailDomain = DomainFilter.getIdpsForEmailDomain(identityProviderProvisioning.retrieveActive(identityZoneManager.getCurrentIdentityZoneId()), user.getEmails().getFirst().getValue());
            idpsForEmailDomain = idpsForEmailDomain.stream().filter(idp -> !idp.getOriginKey().equals(OriginKeys.UAA)).toList();
            if (!idpsForEmailDomain.isEmpty()) {
                List<String> idpOrigins = idpsForEmailDomain.stream().map(IdentityProvider::getOriginKey).toList();
                throw new ScimException("The user account is set up for single sign-on. Please use one of these origin(s) : %s".formatted(idpOrigins.toString()), HttpStatus.BAD_REQUEST);
            }
            passwordValidator.validate(user.getPassword());
        }

        user.setZoneId(identityZoneManager.getCurrentIdentityZoneId());

        if (!aliasHandler.aliasPropertiesAreValid(user, null)) {
            throw new ScimException("Alias ID and/or alias ZID are invalid.", HttpStatus.BAD_REQUEST);
        }

        final ScimUser scimUser;
        if (aliasEntitiesEnabled) {
            // create the user and an alias for it if necessary
            scimUser = createScimUserWithAliasHandling(user);
        } else {
            // create the user without alias handling
            scimUser = scimUserProvisioning.createUser(user, user.getPassword(), identityZoneManager.getCurrentIdentityZoneId());
        }

        if (user.getApprovals() != null) {
            for (Approval approval : user.getApprovals()) {
                approval.setUserId(scimUser.getId());
                approvalStore.addApproval(approval, identityZoneManager.getCurrentIdentityZoneId());
            }
        }
        final ScimUser scimUserWithApprovalsAndGroups = syncApprovals(syncGroups(scimUser));
        addETagHeader(response, scimUserWithApprovalsAndGroups);
        return scimUserWithApprovalsAndGroups;
    }

    private ScimUser createScimUserWithAliasHandling(final ScimUser user) {
        final ScimUser scimUser;
        try {
            scimUser = transactionTemplate.execute(txStatus -> {
                final ScimUser originalScimUser = scimUserProvisioning.createUser(
                        user,
                        user.getPassword(),
                        identityZoneManager.getCurrentIdentityZoneId()
                );
                return aliasHandler.ensureConsistencyOfAliasEntity(
                        originalScimUser,
                        null
                );
            });
        } catch (final EntityAliasFailedException e) {
            throw new ScimException(e.getMessage(), e, HttpStatus.resolve(e.getHttpStatus()));
        }
        if (scimUser == null) {
            throw new IllegalStateException("The persisted user is not present after handling the alias.");
        }
        return scimUser;
    }

    private boolean isUaaUser(@RequestBody ScimUser user) {
        return OriginKeys.UAA.equals(user.getOrigin());
    }

    @PutMapping("/Users/{userId}")
    @ResponseBody
    public ScimUser updateUser(@RequestBody ScimUser user, @PathVariable String userId,
                               @RequestHeader(value = "If-Match", required = false, defaultValue = "NaN") String etag,
                               HttpServletRequest request,
                               HttpServletResponse httpServletResponse,
                               OAuth2Authentication authentication) {

        throwWhenUserManagementIsDisallowed(user.getOrigin(), request);
        throwWhenInvalidSelfEdit(user, userId, request, authentication);

        if ("NaN".equals(etag)) {
            throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
        }
        int version = getVersion(userId, etag);
        user.setVersion(version);

        user.setZoneId(identityZoneManager.getCurrentIdentityZoneId());

        final ScimUser scimUser;
        try {
            scimUser = scimUserService.updateUser(userId, user);
        } catch (final AliasPropertiesInvalidException e) {
            throw new ScimException("The fields 'aliasId' and/or 'aliasZid' are invalid.", HttpStatus.BAD_REQUEST);
        } catch (final OptimisticLockingFailureException e) {
            throw new ScimResourceConflictException(e.getMessage());
        } catch (final EntityAliasFailedException e) {
            throw new ScimException(e.getMessage(), e, HttpStatus.resolve(e.getHttpStatus()));
        }

        scimUpdates.incrementAndGet();
        final ScimUser scimUserWithApprovalsAndGroups = syncApprovals(syncGroups(scimUser));
        addETagHeader(httpServletResponse, scimUserWithApprovalsAndGroups);
        return scimUserWithApprovalsAndGroups;
    }

    @PatchMapping("/Users/{userId}")
    @ResponseBody
    public ScimUser patchUser(@RequestBody ScimUser patch, @PathVariable String userId,
                              @RequestHeader(value = "If-Match", required = false, defaultValue = "NaN") String etag,
                              HttpServletRequest request,
                              HttpServletResponse response,
                              OAuth2Authentication authentication) {

        if ("NaN".equals(etag)) {
            throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
        }

        int version = getVersion(userId, etag);
        ScimUser existing = scimUserProvisioning.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId());
        try {
            existing.patch(patch);
            existing.setVersion(version);
            if (existing.getEmails() != null && existing.getEmails().size() > 1) {
                String primary = existing.getPrimaryEmail();
                existing.setEmails(new ArrayList<>());
                existing.setPrimaryEmail(primary);
            }
            return updateUser(existing, userId, etag, request, response, authentication);
        } catch (IllegalArgumentException x) {
            throw new InvalidScimResourceException(x.getMessage());
        }
    }

    @DeleteMapping("/Users/{userId}")
    @ResponseBody
    @Transactional
    public ScimUser deleteUser(@PathVariable String userId,
                               @RequestHeader(value = "If-Match", required = false) String etag,
                               HttpServletRequest request,
                               HttpServletResponse httpServletResponse) {
        int version = etag == null ? -1 : getVersion(userId, etag);
        ScimUser user = getUser(userId, httpServletResponse);
        throwWhenUserManagementIsDisallowed(user.getOrigin(), request);

        final boolean userHasAlias = hasText(user.getAliasZid());
        if (userHasAlias && !aliasEntitiesEnabled) {
            throw new UaaException(
                    "Could not delete user with alias since alias entities are disabled.",
                    HttpStatus.BAD_REQUEST.value()
            );
        }

        membershipManager.removeMembersByMemberId(userId, identityZoneManager.getCurrentIdentityZoneId());
        scimUserProvisioning.delete(userId, version, identityZoneManager.getCurrentIdentityZoneId());
        scimDeletes.incrementAndGet();
        if (publisher != null) {
            publisher.publishEvent(
                    new EntityDeletedEvent<>(
                            user,
                            SecurityContextHolder.getContext().getAuthentication(),
                            identityZoneManager.getCurrentIdentityZoneId())
            );
            logger.debug("User delete event sent[{}]", user.getId());
        }

        if (!userHasAlias) {
            // no further action necessary
            return user;
        }

        // also delete alias user, if present
        final Optional<ScimUser> aliasUserOpt = aliasHandler.retrieveAliasEntity(user);
        if (aliasUserOpt.isEmpty()) {
            // ignore dangling reference to alias user
            logger.warn("Attempted to delete alias of user '{}', but it was not present.", user.getId());
            return user;
        }
        final ScimUser aliasUser = aliasUserOpt.get();
        membershipManager.removeMembersByMemberId(aliasUser.getId(), aliasUser.getZoneId());
        scimUserProvisioning.delete(aliasUser.getId(), aliasUser.getVersion(), aliasUser.getZoneId());
        if (publisher != null) {
            publisher.publishEvent(
                    new EntityDeletedEvent<>(
                            aliasUser,
                            SecurityContextHolder.getContext().getAuthentication(),
                            aliasUser.getZoneId()
                    )
            );
            logger.debug("User delete event sent[{}]", aliasUser.getId());
        }

        return user;
    }

    @GetMapping("/Users/{userId}/verify-link")
    @ResponseBody
    public ResponseEntity<VerificationResponse> getUserVerificationLink(@PathVariable String userId,
                                                                        @RequestParam(value = "client_id", required = false) String clientId,
                                                                        @RequestParam(value = "redirect_uri") String redirectUri) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2Authentication oAuth2Authentication) {

            if (clientId == null) {
                clientId = oAuth2Authentication.getOAuth2Request().getClientId();
            }
        }

        VerificationResponse responseBody = new VerificationResponse();

        ScimUser user = scimUserProvisioning.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId());
        if (user.isVerified()) {
            throw new UserAlreadyVerifiedException();
        }

        ExpiringCode expiringCode = ScimUtils.getExpiringCode(codeStore, userId, user.getPrimaryEmail(), clientId, redirectUri, REGISTRATION, identityZoneManager.getCurrentIdentityZoneId());
        responseBody.setVerifyLink(ScimUtils.getVerificationURL(expiringCode, identityZoneManager.getCurrentIdentityZone()));

        return new ResponseEntity<>(responseBody, HttpStatus.OK);
    }

    @GetMapping("/Users/{userId}/verify")
    @ResponseBody
    public ScimUser verifyUser(@PathVariable String userId,
                               @RequestHeader(value = "If-Match", required = false) String etag,
                               HttpServletResponse httpServletResponse) {
        int version = etag == null ? -1 : getVersion(userId, etag);
        ScimUser user = scimUserProvisioning.verifyUser(userId, version, identityZoneManager.getCurrentIdentityZoneId());
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
        if ("*".equals(value)) {
            return scimUserProvisioning.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId()).getVersion();
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new ScimException("Invalid version match header (should be a version number): " + etag,
                    HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/Users")
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

        List<ScimUser> input = new ArrayList<>();
        List<ScimUser> result;
        Set<String> attributes = StringUtils.commaDelimitedListToSet(attributesCommaSeparated);
        try {
            result = scimUserProvisioning.query(filter, sortBy, "ascending".equals(sortOrder), identityZoneManager.getCurrentIdentityZoneId());
            for (ScimUser user : UaaPagingUtils.subList(result, startIndex, count)) {
                if (attributes.isEmpty() || attributes.stream().anyMatch("groups"::equalsIgnoreCase)) {
                    syncGroups(user);
                }
                if (attributes.isEmpty() || attributes.stream().anyMatch("approvals"::equalsIgnoreCase)) {
                    syncApprovals(user);
                }
                input.add(user);
            }
        } catch (IllegalArgumentException e) {
            String msg = "Invalid filter expression: [" + filter + "]";
            if (hasText(sortBy)) {
                msg += " [" + sortBy + "]";
            }
            throw new ScimException(HtmlUtils.htmlEscape(msg), HttpStatus.BAD_REQUEST);
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
                    attributes.toArray(new String[0]),
                    mapper,
                    Arrays.asList(ScimCore.SCHEMAS)
            );
        } catch (JsonPathException e) {
            throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
        }
    }

    @PatchMapping("/Users/{userId}/status")
    public UserAccountStatus updateAccountStatus(@RequestBody UserAccountStatus status, @PathVariable String userId) {
        ScimUser user = scimUserProvisioning.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId());

        if (!user.getOrigin().equals(OriginKeys.UAA)) {
            throw new IllegalArgumentException("Can only manage users from the internal user store.");
        }
        if (status.getLocked() != null && status.getLocked()) {
            throw new IllegalArgumentException("Cannot set user account to locked. User accounts only become locked through exceeding the allowed failed login attempts.");
        }
        if (status.getPasswordChangeRequired() != null && !status.getPasswordChangeRequired()) {
            throw new IllegalArgumentException("The requirement that this user change their password cannot be removed via API.");
        }


        if (status.getLocked() != null && !status.getLocked()) {
            publish(new UserAccountUnlockedEvent(user, identityZoneManager.getCurrentIdentityZoneId()));
        }
        if (status.getPasswordChangeRequired() != null && status.getPasswordChangeRequired()) {
            scimUserProvisioning.updatePasswordChangeRequired(userId, true, identityZoneManager.getCurrentIdentityZoneId());
        }

        return status;
    }

    @Nullable
    private ScimUser syncGroups(@Nullable ScimUser user) {
        if (user == null) {
            return null;
        }

        Set<ScimGroup> directGroups = membershipManager.getGroupsWithMember(user.getId(), false, identityZoneManager.getCurrentIdentityZoneId());
        Set<ScimGroup> indirectGroups = membershipManager.getGroupsWithMember(user.getId(), true, identityZoneManager.getCurrentIdentityZoneId());
        indirectGroups.removeAll(directGroups);
        Set<ScimUser.Group> groups = new HashSet<>();
        for (ScimGroup group : directGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.DIRECT));
        }
        for (ScimGroup group : indirectGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.INDIRECT));
        }

        user.setGroups(groups);
        return user;
    }

    /**
     * Look up the approvals for the given user and keep only those that are currently active.
     */
    private ScimUser syncApprovals(ScimUser user) {
        if (user == null || approvalStore == null) {
            return user;
        }
        Set<Approval> approvals = new HashSet<>(approvalStore.getApprovalsForUser(user.getId(), identityZoneManager.getCurrentIdentityZoneId()));
        Set<Approval> active = new HashSet<>(approvals);
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
        logger.info("Handling error: {}, {}", e.getClass().getSimpleName(), e.getMessage());
        if (e instanceof InternalUserManagementDisabledException) {
            throw e;
        }
        return new ResponseEntity<>(e, HttpStatus.valueOf(e.getHttpStatus()));
    }

    @ExceptionHandler
    public View handleException(Exception t, HttpServletRequest request) throws ScimException, InternalUserManagementDisabledException {
        logger.error("Unhandled exception in SCIM user endpoints. {}", t.getMessage());

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
                for (Class<?> key : statuses.keySet()) {
                    if (key.isAssignableFrom(clazz)) {
                        e = new ScimException(t.getMessage(), t, statuses.get(key));
                        break;
                    }
                }
            }
        }
        incrementErrorCounts(e);
        // User can supply trace=true or just trace (unspecified) to get stack
        // traces
        boolean trace = request.getParameter("trace") != null && !"false".equals(request.getParameter("trace"));
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
                    errorCounts.computeIfAbsent(series, k -> new AtomicInteger(1));
                    return;
                }
            }
        }
        value.incrementAndGet();
    }

    private void publish(ApplicationEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(scimUserProvisioning, "ScimUserProvisioning must be set");
        Assert.notNull(membershipManager, "ScimGroupMembershipManager must be set");
        Assert.notNull(approvalStore, "ApprovalStore must be set");
    }

    private void addETagHeader(HttpServletResponse httpServletResponse, ScimUser scimUser) {
        if (scimUser == null) {
            throw new ScimException("Missing SCIM User", HttpStatus.BAD_REQUEST);
        }
        httpServletResponse.setHeader(E_TAG, "\"" + scimUser.getVersion() + "\"");
    }

    @Override
    public void setApplicationEventPublisher(@NonNull ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    private void throwWhenUserManagementIsDisallowed(String origin, HttpServletRequest request) {
        Object attr = request.getAttribute(DisableInternalUserManagementFilter.DISABLE_INTERNAL_USER_MANAGEMENT);
        if (attr instanceof Boolean isUserManagementDisabled) {
            if (isUserManagementDisabled && (OriginKeys.UAA.equals(origin) || !hasLength(origin))) {
                throw new InternalUserManagementDisabledException(DisableUserManagementSecurityFilter.INTERNAL_USER_CREATION_IS_CURRENTLY_DISABLED);
            }
        }
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

    private static class InvalidSelfEditException extends UaaException {
        InvalidSelfEditException() {
            super("invalid_self_edit",
                    "Users are only allowed to edit their own User settings when internal user storage is enabled, " +
                            "and in that case they may only edit the givenName and familyName.",
                    403
            );
        }
    }
}
