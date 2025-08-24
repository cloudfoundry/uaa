package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.account.EmailChange;
import org.cloudfoundry.identity.uaa.account.EmailChangeResponse;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.sql.Timestamp;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.EMAIL;
import static org.springframework.http.HttpStatus.*;

@Controller
public class ChangeEmailEndpoints implements ApplicationEventPublisherAware {

    private static final long EMAIL_CHANGE_LIFETIME = Duration.ofMinutes(30L).toMillis();
    private static final String CHANGE_EMAIL_REDIRECT_URL = "change_email_redirect_url";

    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private final QueryableResourceManager<ClientDetails> clientDetailsService;
    private final IdentityZoneManager identityZoneManager;

    private ApplicationEventPublisher publisher;

    public ChangeEmailEndpoints(
            final ScimUserProvisioning scimUserProvisioning,
            final ExpiringCodeStore expiringCodeStore,
            final QueryableResourceManager<ClientDetails> clientDetailsService,
            final IdentityZoneManager identityZoneManager) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
        this.clientDetailsService = clientDetailsService;
        this.identityZoneManager = identityZoneManager;
    }

    @PostMapping("/email_verifications")
    public ResponseEntity<String> generateEmailVerificationCode(@RequestBody EmailChange emailChange) {
        final String userId = emailChange.getUserId();
        final String email = emailChange.getEmail();

        final ScimUser user = scimUserProvisioning.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId());
        if (user.getUserName().equals(user.getPrimaryEmail())) {
            final List<ScimUser> results = scimUserProvisioning.retrieveByUsernameAndOriginAndZone(email, OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());
            if (!results.isEmpty()) {
                return new ResponseEntity<>(CONFLICT);
            }
        }

        try {
            final String code = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(emailChange), new Timestamp(System.currentTimeMillis() + EMAIL_CHANGE_LIFETIME), EMAIL.name(), identityZoneManager.getCurrentIdentityZoneId()).getCode();
            return new ResponseEntity<>(code, CREATED);
        } catch (JsonUtils.JsonUtilException e) {
            throw new UaaException("Error while generating change email code", e);
        }
    }

    @PostMapping("/email_changes")
    public ResponseEntity<EmailChangeResponse> changeEmail(@RequestBody String code) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code, identityZoneManager.getCurrentIdentityZoneId());
        if ((null != expiringCode) && ((null == expiringCode.getIntent()) || EMAIL.name().equals(expiringCode.getIntent()))) {
            Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<>() {
            });
            assert data != null;
            String userId = data.get("userId");
            String email = data.get("email");
            ScimUser user = scimUserProvisioning.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId());
            if (user.getUserName().equals(user.getPrimaryEmail())) {
                user.setUserName(email);
            }
            user.setPrimaryEmail(email);

            scimUserProvisioning.update(userId, user, identityZoneManager.getCurrentIdentityZoneId());

            String redirectLocation = null;
            String clientId = data.get("client_id");

            if (clientId != null && !"".equals(clientId)) {
                ClientDetails clientDetails = clientDetailsService.retrieve(clientId, identityZoneManager.getCurrentIdentityZoneId());
                redirectLocation = (String) clientDetails.getAdditionalInformation().get(CHANGE_EMAIL_REDIRECT_URL);
            }

            publisher.publishEvent(UserModifiedEvent.emailChanged(user, identityZoneManager.getCurrentIdentityZoneId()));

            EmailChangeResponse emailChangeResponse = new EmailChangeResponse();
            emailChangeResponse.setEmail(email);
            emailChangeResponse.setUserId(userId);
            emailChangeResponse.setUsername(user.getUserName());
            emailChangeResponse.setRedirectUrl(redirectLocation);
            return new ResponseEntity<>(emailChangeResponse, OK);
        } else {
            return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
        }
    }

    @Override
    public void setApplicationEventPublisher(@NonNull ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

}
