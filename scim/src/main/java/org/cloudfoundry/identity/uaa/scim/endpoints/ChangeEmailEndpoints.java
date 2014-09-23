package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.IOException;
import java.util.Map;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.OK;

@Controller
public class ChangeEmailEndpoints {
    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private final ObjectMapper objectMapper;

    public ChangeEmailEndpoints(ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore, ObjectMapper objectMapper) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
        this.objectMapper = objectMapper;
    }

    @RequestMapping(value="/email_changes", method = RequestMethod.POST)
    public ResponseEntity changeEmail(@RequestBody String code) throws IOException {
        ResponseEntity<Map<String,String>> responseEntity;
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code);
        if (expiringCode != null) {
            Map<String, String> data = objectMapper.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
            String userId = data.get("userId");
            String email = data.get("email");
            ScimUser user = scimUserProvisioning.retrieve(userId);
            user.setPrimaryEmail(email);
            scimUserProvisioning.update(userId, user);
            responseEntity = new ResponseEntity<>(OK);
        }
        else {
            responseEntity = new ResponseEntity<>(BAD_REQUEST);
        }

        return responseEntity;
    }
}
