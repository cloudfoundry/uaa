/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.domain.standard;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimEmail;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimName;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimPhoneNumber;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimUserGroupInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimUserInterface;
import org.cloudfoundry.identity.uaa.scim.json.ScimUserJsonDeserializer;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Object to hold SCIM data for Jackson to map to and from JSON
 *
 * See the <a
 * href="http://www.simplecloud.info/specs/draft-scim-core-schema-02.html">SCIM
 * user schema</a>.
 *
 * @author Luke Taylor
 */
@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
@JsonDeserialize(using = ScimUserJsonDeserializer.class)
public class ScimUser extends ScimCore implements ScimUserInterface {

    private String userName;

    private ScimName name;

    private List<ScimEmail> emails;

    private Set<ScimUserGroupInterface> groups;

    private Set<Approval> approvals;

    private List<ScimPhoneNumber> phoneNumbers;

    private String displayName;

    private String nickName;

    private String profileUrl;

    private String title;;

    private String userType;

    private String preferredLanguage;

    private String locale;

    private String timezone;

    private boolean active = true;

    private boolean verified = false;

    @JsonProperty
    private String password;

    public ScimUser() {
    }

    public ScimUser(String id, String userName, String givenName, String familyName) {
        super(id);
        this.userName = userName;
        this.name = new ScimName(givenName, familyName);
    }

    @Override
    public String getUserName() {
        return userName;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public void setUserName(String userName) {
        this.userName = userName;
    }

    @Override
    public ScimName getName() {
        return name;
    }

    @Override
    public void setName(ScimName name) {
        this.name = name;
    }

    @Override
    public List<ScimEmail> getEmails() {
        return emails;
    }

    @Override
    public void setEmails(List<ScimEmail> emails) {
        this.emails = emails;
    }

    @Override
    public Set<Approval> getApprovals() {
        return approvals;
    }

    @Override
    public void setApprovals(Set<Approval> approvals) {
        this.approvals = approvals;
    }

    @Override
    public Set<ScimUserGroupInterface> getGroups() {
        return groups;
    }

    @Override
    public void setGroups(Collection<ScimUserGroupInterface> groups) {
        this.groups = new LinkedHashSet<ScimUserGroupInterface>();
        for (ScimUserGroupInterface item : groups)
        {
            this.groups.add((ScimUserGroup) item);
        }
    }

    @Override
    public List<ScimPhoneNumber> getPhoneNumbers() {
        return phoneNumbers;
    }

    @Override
    public void setPhoneNumbers(List<ScimPhoneNumber> phoneNumbers) {
        if (phoneNumbers!=null && phoneNumbers.size()>0) {
            ArrayList<ScimPhoneNumber> list = new ArrayList<ScimPhoneNumber>();
            list.addAll(phoneNumbers);
            for (int i=(list.size()-1); i>=0; i--) {
                ScimPhoneNumber pn = list.get(i);
                if (pn==null || (!StringUtils.hasText(pn.getValue()))) {
                    list.remove(i);
                }
            }
            phoneNumbers = list;
        }
        this.phoneNumbers = phoneNumbers;
    }

    @Override
    public String getDisplayName() {
        return displayName;
    }

    @Override
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public String getNickName() {
        return nickName;
    }

    @Override
    public void setNickName(String nickName) {
        this.nickName = nickName;
    }

    @Override
    public String getProfileUrl() {
        return profileUrl;
    }

    @Override
    public void setProfileUrl(String profileUrl) {
        this.profileUrl = profileUrl;
    }

    @Override
    public String getTitle() {
        return title;
    }

    @Override
    public void setTitle(String title) {
        this.title = title;
    }

    @Override
    public String getUserType() {
        return userType;
    }

    @Override
    public void setUserType(String userType) {
        this.userType = userType;
    }

    @Override
    public String getPreferredLanguage() {
        return preferredLanguage;
    }

    @Override
    public void setPreferredLanguage(String preferredLanguage) {
        this.preferredLanguage = preferredLanguage;
    }

    @Override
    public String getLocale() {
        return locale;
    }

    @Override
    public void setLocale(String locale) {
        this.locale = locale;
    }

    @Override
    public String getTimezone() {
        return timezone;
    }

    @Override
    public void setTimezone(String timezone) {
        this.timezone = timezone;
    }

    @Override
    public boolean isActive() {
        return active;
    }

    @Override
    public void setActive(boolean active) {
        this.active = active;
    }

    @Override
    public boolean isVerified() {
        return verified;
    }

    @Override
    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    @Override
    @JsonIgnore
    public String getPrimaryEmail() {
        if (getEmails() == null || getEmails().isEmpty()) {
            return null;
        }

        ScimEmail primaryEmail = null;

        for (ScimEmail email : getEmails()) {
            if (email.isPrimary()) {
                primaryEmail = email;
                break;
            }
        }

        if (primaryEmail == null) {
            primaryEmail = getEmails().get(0);
        }

        return primaryEmail.getValue();
    }

    @Override
    @JsonIgnore
    public String getGivenName() {
        return name == null ? null : name.getGivenName();
    }

    @Override
    @JsonIgnore
    public String getFamilyName() {
        return name == null ? null : name.getFamilyName();
    }

    /**
     * Adds a new email address, ignoring "type" and "primary" fields, which we
     * don't need yet
     */
    @Override
    public void addEmail(String newEmail) {
        Assert.hasText(newEmail);

        if (emails == null) {
            emails = new ArrayList<ScimEmail>(1);
        }
        for (ScimEmail email : emails) {
            if (email.getValue().equals(newEmail)) {
                throw new IllegalArgumentException("Already contains email " + newEmail);
            }
        }

        ScimEmail e = new ScimEmail();
        e.setValue(newEmail);
        emails.add(e);
    }

    /**
     * Adds a new phone number with null type.
     *
     * @param newPhoneNumber
     */
    @Override
    public void addPhoneNumber(String newPhoneNumber) {
        Assert.hasText(newPhoneNumber);

        if (phoneNumbers == null) {
            phoneNumbers = new ArrayList<ScimPhoneNumber>(1);
        }
        for (ScimPhoneNumber email : phoneNumbers) {
            if (email.getValue().equals(newPhoneNumber) && email.getType() == null) {
                throw new IllegalArgumentException("Already contains phoneNumber " + newPhoneNumber);
            }
        }

        ScimPhoneNumber e = new ScimPhoneNumber();
        e.setValue(newPhoneNumber);
        phoneNumbers.add(e);
    }

    /**
     * Creates a word list from the user data for use in password checking
     * implementations
     */
    @Override
    public List<String> wordList() {
        List<String> words = new ArrayList<String>();

        if (userName != null) {
            words.add(userName);
        }

        if (name != null) {
            if (name.getGivenName() != null) {
                words.add(name.getGivenName());
            }
            if (name.getFamilyName() != null) {
                words.add(name.getFamilyName());
            }
            if (nickName != null) {
                words.add(nickName);
            }
        }

        if (emails != null) {
            for (ScimEmail email : emails) {
                words.add(email.getValue());
            }
        }

        return words;
    }

}
