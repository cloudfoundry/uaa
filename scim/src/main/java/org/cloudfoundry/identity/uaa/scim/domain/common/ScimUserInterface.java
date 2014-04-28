package org.cloudfoundry.identity.uaa.scim.domain.common;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.scim.json.ScimUserJsonDeserializer;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
@JsonDeserialize(using = ScimUserJsonDeserializer.class)
public interface ScimUserInterface extends ScimCoreInterface
{
    String getUserName();

    String getPassword();

    void setPassword(String password);

    void setUserName(String userName);

    ScimName getName();

    void setName(ScimName name);

    List<ScimEmail> getEmails();

    void setEmails(List<ScimEmail> emails);

    Set<Approval> getApprovals();

    void setApprovals(Set<Approval> approvals);

    Set<ScimUserGroupInterface> getGroups();

    void setGroups(Collection<ScimUserGroupInterface> groups);

    List<ScimPhoneNumber> getPhoneNumbers();

    void setPhoneNumbers(List<ScimPhoneNumber> phoneNumbers);

    String getDisplayName();

    void setDisplayName(String displayName);

    String getNickName();

    void setNickName(String nickName);

    String getProfileUrl();

    void setProfileUrl(String profileUrl);

    String getTitle();

    void setTitle(String title);

    String getUserType();

    void setUserType(String userType);

    String getPreferredLanguage();

    void setPreferredLanguage(String preferredLanguage);

    String getLocale();

    void setLocale(String locale);

    String getTimezone();

    void setTimezone(String timezone);

    boolean isActive();

    void setActive(boolean active);

    boolean isVerified();

    void setVerified(boolean verified);

    @JsonIgnore
    String getPrimaryEmail();

    @JsonIgnore
    String getGivenName();

    @JsonIgnore
    String getFamilyName();

    /**
     * Adds a new email address, ignoring "type" and "primary" fields, which we
     * don't need yet
     */
    void addEmail(String newEmail);

    /**
     * Adds a new phone number with null type.
     *
     * @param newPhoneNumber
     */
    void addPhoneNumber(String newPhoneNumber);

    /**
     * Creates a word list from the user data for use in password checking
     * implementations
     */
    List<String> wordList();

}
