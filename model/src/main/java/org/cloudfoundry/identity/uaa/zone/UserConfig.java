package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.lang.Nullable;

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

    // in addition to defaultGroups, which are implicitely allowed
    private List<String> allowedGroups;

    private int maxUsers = -1;

    private boolean checkOriginEnabled;

    private boolean allowOriginLoop = true;

    public List<String> getDefaultGroups() {
        return defaultGroups;
    }

    public void setDefaultGroups(List<String> defaultGroups) {
        this.defaultGroups = defaultGroups;
    }

    public List<String> getAllowedGroups() {
        return allowedGroups;
    }

    public void setAllowedGroups(List<String> allowedGroups) {
        this.allowedGroups = allowedGroups;
    }

    public boolean allGroupsAllowed() {
        return allowedGroups == null;
    }

    // return defaultGroups plus allowedGroups
    @Nullable
    public Set<String> resultingAllowedGroups() {
        if (allGroupsAllowed()) {
            return null; // null = all groups allowed
        } else {
            HashSet<String> allAllowedGroups = new HashSet<>(allowedGroups);
            if (defaultGroups != null) {
                allAllowedGroups.addAll(defaultGroups);
            }
            return allAllowedGroups;
        }
    }

    public int getMaxUsers() {
        return this.maxUsers;
    }

    public void setMaxUsers(int maxUsers) {
        this.maxUsers = maxUsers;
    }

    public boolean isCheckOriginEnabled() {
        return this.checkOriginEnabled;
    }

    public void setCheckOriginEnabled(boolean checkOriginEnabled) {
        this.checkOriginEnabled = checkOriginEnabled;
    }

    public boolean isAllowOriginLoop() {
        return this.allowOriginLoop;
    }

    public void setAllowOriginLoop(final boolean allowAllOrigins) {
        this.allowOriginLoop = allowAllOrigins;
    }
}
