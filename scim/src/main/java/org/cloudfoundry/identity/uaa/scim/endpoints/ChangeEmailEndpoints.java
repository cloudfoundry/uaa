package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.codehaus.jackson.annotate.JsonProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

public class ChangeEmailEndpoints {
    private final ScimUserProvisioning scimUserProvisioning;

    public ChangeEmailEndpoints(ScimUserProvisioning scimUserProvisioning) {
        this.scimUserProvisioning = scimUserProvisioning;
    }

    @RequestMapping(value="/email_changes", method = RequestMethod.POST)
    public ResponseEntity changeEmail(@RequestBody EmailChange emailChange) {
        String userId = emailChange.getUserId();
        ScimUser user = scimUserProvisioning.retrieve(userId);
        user.setPrimaryEmail(emailChange.getNewEmail());

        scimUserProvisioning.update(userId, user);

        return new ResponseEntity(HttpStatus.OK);
    }

    public static class EmailChange {

        @JsonProperty("newEmail")
        private String newEmail;

        @JsonProperty("userId")
        private String userId;

        public String getNewEmail() {
            return newEmail;
        }

        public void setNewEmail(String newEmail) {
            this.newEmail = newEmail;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }
    }
}
