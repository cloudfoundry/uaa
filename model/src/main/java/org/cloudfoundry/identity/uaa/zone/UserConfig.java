package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserConfig {

    public static List<String> DEFAULT_ZONE_GROUPS = List.of("openid",
            "password.write",
            "uaa.user",
            "approvals.me",
            "profile",
            "roles",
            "user_attributes",
            "uaa.offline_token");

    private List<String> defaultGroups = DEFAULT_ZONE_GROUPS;

    private int maxUsers = -1;

    public List<String> getDefaultGroups() {
        return defaultGroups;
    }

    public void setDefaultGroups(List<String> defaultGroups) {
        this.defaultGroups = defaultGroups;
    }

    public int getMaxUsers() {
        return this.maxUsers;
    }

    public void setMaxUsers(final int maxUsers) {
        this.maxUsers = maxUsers > 0 && maxUsers < Integer.MAX_VALUE ? maxUsers : -1;
    }
}
