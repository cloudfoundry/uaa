package org.cloudfoundry.identity.uaa.approval;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.resources.ActionResult;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.UaaPagingUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.web.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.HttpMediaTypeException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.View;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Controller
@RequiredArgsConstructor
@Slf4j
public class ApprovalsAdminEndpoints implements InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalsAdminEndpoints.class);
    private static final Map<Class<? extends Exception>, HttpStatus> statuses;

    static {
        statuses = Map.of(
                DataIntegrityViolationException.class, BAD_REQUEST,
                HttpMessageConversionException.class, BAD_REQUEST,
                HttpMediaTypeException.class, BAD_REQUEST,
                IllegalArgumentException.class, BAD_REQUEST,
                UnsupportedOperationException.class, BAD_REQUEST,
                BadSqlGrammarException.class, BAD_REQUEST);
    }

    private final SecurityContextAccessor securityContextAccessor;
    private final ApprovalStore approvalStore;
    private final UaaUserDatabase userDatabase;
    private final MultitenantClientServices clientDetailsService;
    private final IdentityZoneManager identityZoneManager;
    private final HttpMessageConverter<?>[] messageConverters = new HttpMessageConverter[]{
            new ExceptionReportHttpMessageConverter()
    };

    @GetMapping("/approvals")
    @ResponseBody
    public List<Approval> getApprovals(@RequestParam(required = false, defaultValue = "user_id pr") String ignored,
            @RequestParam(required = false, defaultValue = "1") int startIndex,
            @RequestParam(required = false, defaultValue = "100") int count) {
        String userId = getCurrentUserId();
        logger.debug("Fetching all approvals for user: {}", userId);
        List<Approval> input = approvalStore.getApprovalsForUser(userId, identityZoneManager.getCurrentIdentityZoneId());
        List<Approval> approvals = UaaPagingUtils.subList(input, startIndex, count);

        // Find the clients for these approvals
        Set<String> clientIds = new HashSet<>();
        for (Approval approval : approvals) {
            clientIds.add(approval.getClientId());
        }

        // Find the auto approved scopes for these clients
        Map<String, Set<String>> clientAutoApprovedScopes = new HashMap<>();
        for (String clientId : clientIds) {
            UaaClientDetails client = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());

            Set<String> autoApproved = client.getAutoApproveScopes();
            Set<String> autoApprovedScopes = new HashSet<>();
            if (autoApproved != null) {
                if (autoApproved.contains("true")) {
                    autoApprovedScopes.addAll(client.getScope());
                } else {
                    autoApprovedScopes.addAll(autoApproved);
                }
            }

            clientAutoApprovedScopes.put(clientId, autoApprovedScopes);
        }

        List<Approval> filteredApprovals = new ArrayList<>();
        // Remove auto approved scopes
        for (Approval approval : approvals) {
            if (!(clientAutoApprovedScopes.containsKey(approval.getClientId())
                    && clientAutoApprovedScopes.get(approval.getClientId()).contains(approval.getScope()))) {
                filteredApprovals.add(approval);
            }
        }

        return filteredApprovals;
    }

    private String getCurrentUserId() {
        if (!securityContextAccessor.isUser()) {
            throw new AccessDeniedException("Approvals can only be managed by a user");
        }
        return securityContextAccessor.getUserId();
    }

    @PutMapping("/approvals")
    @ResponseBody
    public List<Approval> updateApprovals(@RequestBody Approval[] approvals) {
        String currentUserId = getCurrentUserId();
        logger.debug("Updating approvals for user: {}", currentUserId);
        approvalStore.revokeApprovalsForUser(currentUserId, identityZoneManager.getCurrentIdentityZoneId());
        List<Approval> result = new LinkedList<>();
        for (Approval approval : approvals) {
            if (StringUtils.hasText(approval.getUserId()) && !isValidUser(approval.getUserId())) {
                if (logger.isWarnEnabled()) {
                    logger.warn("Error[2] {} attempting to update approvals for {}",
                            UaaStringUtils.getCleanedUserControlString(currentUserId),
                            UaaStringUtils.getCleanedUserControlString(approval.getUserId()));
                }
                throw new UaaException("unauthorized_operation", "Cannot update approvals for another user. Set user_id to null to update for existing user.",
                        HttpStatus.UNAUTHORIZED.value());
            } else {
                approval.setUserId(currentUserId);
            }
            if (approvalStore.addApproval(approval, identityZoneManager.getCurrentIdentityZoneId())) {
                result.add(approval);
            }
        }
        return result;
    }

    @PutMapping("/approvals/{clientId}")
    @ResponseBody
    public List<Approval> updateClientApprovals(@PathVariable String clientId, @RequestBody Approval[] approvals) {
        clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
        String currentUserId = getCurrentUserId();
        logger.debug("Updating approvals for user: {}", currentUserId);
        approvalStore.revokeApprovalsForClientAndUser(clientId, currentUserId, identityZoneManager.getCurrentIdentityZoneId());
        for (Approval approval : approvals) {
            if (StringUtils.hasText(approval.getUserId()) && !isValidUser(approval.getUserId())) {
                if (logger.isWarnEnabled()) {
                    logger.warn("Error[1] {} attemting to update approvals for {}.",
                            UaaStringUtils.getCleanedUserControlString(currentUserId),
                            UaaStringUtils.getCleanedUserControlString(approval.getUserId()));
                }
                throw new UaaException("unauthorized_operation", "Cannot update approvals for another user. Set user_id to null to update for existing user.",
                        HttpStatus.UNAUTHORIZED.value());
            } else {
                approval.setUserId(currentUserId);
            }
            approvalStore.addApproval(approval, identityZoneManager.getCurrentIdentityZoneId());
        }
        return approvalStore.getApprovals(currentUserId, clientId, identityZoneManager.getCurrentIdentityZoneId());
    }

    private boolean isValidUser(String userId) {
        if (userId == null || !userId.equals(getCurrentUserId())) {
            return false;
        }
        try {
            userDatabase.retrieveUserById(userId);
            return true;
        } catch (UsernameNotFoundException e) {
            return false;
        }
    }

    @DeleteMapping("/approvals")
    @ResponseBody
    public ActionResult revokeApprovals(@RequestParam() String clientId) {
        clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
        String userId = getCurrentUserId();
        if (logger.isDebugEnabled()) {
            logger.debug("Revoking all existing approvals for user: {} and client {}",
                    UaaStringUtils.getCleanedUserControlString(userId),
                    UaaStringUtils.getCleanedUserControlString(clientId));
        }
        approvalStore.revokeApprovalsForClientAndUser(clientId, userId, identityZoneManager.getCurrentIdentityZoneId());
        return new ActionResult("ok", "Approvals of user " + userId + " and client " + clientId + " revoked");
    }

    @ExceptionHandler
    public View handleException(NoSuchClientException nsce) {
        logger.debug("Client not found:{}", nsce.getMessage());
        return handleException(new UaaException(nsce.getMessage(), 404));
    }

    @ExceptionHandler
    public View handleException(Exception t) {
        UaaException e = t instanceof UaaException ue ? ue : new UaaException("Unexpected error",
                "Error accessing user's approvals", HttpStatus.INTERNAL_SERVER_ERROR.value());
        Class<?> clazz = t.getClass();
        for (Map.Entry<Class<? extends Exception>, HttpStatus> entry : statuses.entrySet()) {
            if (entry.getKey().isAssignableFrom(clazz)) {
                e = new UaaException(t.getMessage(), "Error accessing user's approvals", entry.getValue().value());
                break;
            }
        }
        return new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(e, false),
                HttpStatus.valueOf(e.getHttpStatus())), messageConverters);
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(approvalStore, "Please supply an approvals manager");
        Assert.notNull(userDatabase, "Please supply a user database");
    }

}
