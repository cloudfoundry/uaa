package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE, setterVisibility = JsonAutoDetect.Visibility.NONE)
public class LostPasswordChangeRequest {

    @JsonProperty("code")
    private String changeCode;

    @JsonProperty("new_password")
    private String newPassword;

    public LostPasswordChangeRequest() { }

    public LostPasswordChangeRequest(String changeCode, String newPassword) {
        this.changeCode = changeCode;
        this.newPassword = newPassword;
    }

    public String getChangeCode() {
        return changeCode;
    }

    public void setChangeCode(String changeCode) {
        this.changeCode = changeCode;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
