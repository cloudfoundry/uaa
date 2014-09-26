package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.audit.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;

@Controller
public class ChangeEmailEndpoints implements ApplicationEventPublisherAware {
    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private final ObjectMapper objectMapper;
    private ApplicationEventPublisher publisher;
    private static final int EMAIL_CHANGE_LIFETIME = 30 * 60 * 1000;

    public ChangeEmailEndpoints(ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore, ObjectMapper objectMapper) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
        this.objectMapper = objectMapper;
    }

    @RequestMapping(value="/email_verifications", method = RequestMethod.POST)
    public ResponseEntity<String> generateEmailVerificationCode(@RequestBody EmailChange emailChange) {
        String userId = emailChange.getUserId();
        String email = emailChange.getEmail();

        ScimUser user = scimUserProvisioning.retrieve(userId);
        if (user.getUserName().equals(user.getPrimaryEmail())) {
            List<ScimUser> results = scimUserProvisioning.query("userName eq \"" + email + "\" and origin eq \"" + Origin.UAA + "\"");
            if (!results.isEmpty()) {
                    return new ResponseEntity<>(CONFLICT);
            }
        }

        String code;
        try {
            code = expiringCodeStore.generateCode(new ObjectMapper().writeValueAsString(emailChange), new Timestamp(System.currentTimeMillis() + EMAIL_CHANGE_LIFETIME)).getCode();
        } catch (IOException e) {
            throw new UaaException("Error while generating change email code", e);
        }

        return new ResponseEntity<>(code, CREATED);
    }

    @RequestMapping(value="/email_changes", method = RequestMethod.POST)
    public ResponseEntity<EmailChangeResponse> changeEmail(@RequestBody String code) throws IOException {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code);
        if (expiringCode != null) {
            Map<String, String> data = objectMapper.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
            String userId = data.get("userId");
            String email = data.get("email");
            ScimUser user = scimUserProvisioning.retrieve(userId);
            if (user.getUserName().equals(user.getPrimaryEmail())) {
                user.setUserName(email);
            }
            user.setPrimaryEmail(email);

            scimUserProvisioning.update(userId, user);

            publisher.publishEvent(UserModifiedEvent.emailChanged(userId, user.getUserName(), user.getPrimaryEmail()));

            EmailChangeResponse emailChangeResponse = new EmailChangeResponse();
            emailChangeResponse.setEmail(email);
            emailChangeResponse.setUserId(userId);
            emailChangeResponse.setUsername(user.getUserName());
            return new ResponseEntity<>(emailChangeResponse, OK);
        } else {
            return new ResponseEntity<>(BAD_REQUEST);
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public static class EmailChange {
        @JsonProperty("userId")
        private String userId;


        @JsonProperty("email")
        private String email;

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }
    }

    public static class EmailChangeResponse {
        @JsonProperty("username")
        private String username;


        @JsonProperty("userId")
        private String userId;


        @JsonProperty("email")
        private String email;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }
    }
}
