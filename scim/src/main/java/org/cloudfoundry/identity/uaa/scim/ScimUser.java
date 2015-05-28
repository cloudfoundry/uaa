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
package org.cloudfoundry.identity.uaa.scim;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
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
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonDeserialize(using = ScimUserJsonDeserializer.class)
public final class ScimUser extends ScimCore {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Group {
        String value;

        String display;

        public static enum Type {
            DIRECT, INDIRECT
        };

        Type type;

        public Type getType() {
            return type;
        }

        public void setType(Type type) {
            this.type = type;
        }

        public Group() {
            this(null, null);
        }

        public Group(String value, String display) {
            this(value, display, Type.DIRECT);
        }

        public Group(String value, String display, Type type) {
            this.value = value;
            this.display = display;
            this.type = type;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public String getDisplay() {
            return display;
        }

        public void setDisplay(String display) {
            this.display = display;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((display == null) ? 0 : display.hashCode());
            result = prime * result + ((value == null) ? 0 : value.hashCode());
            result = prime * result + ((type == null) ? 0 : type.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            Group other = (Group) obj;
            if (display == null) {
                if (other.display != null)
                    return false;
            }
            else if (!display.equals(other.display))
                return false;
            if (value == null) {
                if (other.value != null)
                    return false;
            }
            else if (!value.equals(other.value))
                return false;
            return type == other.type;
        }

        @Override
        public String toString() {
            return String.format("(id: %s, name: %s, type: %s)", value, display, type);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Name {
        String formatted;

        String familyName;

        String givenName;

        String middleName;

        String honorificPrefix;

        String honorificSuffix;

        public Name() {
        }

        public Name(String givenName, String familyName) {
            this.givenName = givenName;
            this.familyName = familyName;
            this.formatted = givenName + " " + familyName;
        }

        public String getFormatted() {
            return formatted;
        }

        public void setFormatted(String formatted) {
            this.formatted = formatted;
        }

        public String getFamilyName() {
            return familyName;
        }

        public void setFamilyName(String familyName) {
            this.familyName = familyName;
        }

        public String getGivenName() {
            return givenName;
        }

        public void setGivenName(String givenName) {
            this.givenName = givenName;
        }

        public String getMiddleName() {
            return middleName;
        }

        public void setMiddleName(String middleName) {
            this.middleName = middleName;
        }

        public String getHonorificPrefix() {
            return honorificPrefix;
        }

        public void setHonorificPrefix(String honorificPrefix) {
            this.honorificPrefix = honorificPrefix;
        }

        public String getHonorificSuffix() {
            return honorificSuffix;
        }

        public void setHonorificSuffix(String honorificSuffix) {
            this.honorificSuffix = honorificSuffix;
        }

    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Email {
        private String value;

        // this should probably be an enum
        private String type;

        private boolean primary = false;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public void setPrimary(boolean primary) {
            this.primary = primary;
        }

        public boolean isPrimary() {
            return primary;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Email email = (Email) o;

            if (primary != email.primary) return false;
            if (type != null ? !type.equals(email.type) : email.type != null) return false;
            if (value != null ? !value.equals(email.value) : email.value != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = value != null ? value.hashCode() : 0;
            result = 31 * result + (type != null ? type.hashCode() : 0);
            result = 31 * result + (primary ? 1 : 0);
            return result;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class PhoneNumber {
        private String value;

        // this should probably be an enum
        private String type;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

    }

    private String userName;

    private Name name;

    private List<Email> emails;

    private Set<Group> groups;

    private Set<Approval> approvals;

    private List<PhoneNumber> phoneNumbers;

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

    private String origin = "";

    private String externalId = "";

    private String zoneId = null;

    private String salt = null;

    @JsonProperty
    private String password;

    public ScimUser() {
    }

    public ScimUser(String id, String userName, String givenName, String familyName) {
        super(id);
        this.userName = userName;
        this.name = new Name(givenName, familyName);
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public Name getName() {
        return name;
    }

    public void setName(Name name) {
        this.name = name;
    }

    public List<Email> getEmails() {
        return emails;
    }

    public void setEmails(List<Email> emails) {
        this.emails = emails;
    }

    public Set<Approval> getApprovals() {
        return approvals;
    }

    public void setApprovals(Set<Approval> approvals) {
        this.approvals = approvals;
    }

    public Set<Group> getGroups() {
        return groups;
    }

    public void setGroups(Collection<Group> groups) {
        this.groups = new LinkedHashSet<Group>(groups);
    }

    public List<PhoneNumber> getPhoneNumbers() {
        return phoneNumbers;
    }

    public void setPhoneNumbers(List<PhoneNumber> phoneNumbers) {
        if (phoneNumbers!=null && phoneNumbers.size()>0) {
            ArrayList<PhoneNumber> list = new ArrayList<PhoneNumber>();
            list.addAll(phoneNumbers);
            for (int i=(list.size()-1); i>=0; i--) {
                PhoneNumber pn = list.get(i);
                if (pn==null || (!StringUtils.hasText(pn.getValue()))) {
                    list.remove(i);
                }
            }
            phoneNumbers = list;
        }
        this.phoneNumbers = phoneNumbers;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getNickName() {
        return nickName;
    }

    public void setNickName(String nickName) {
        this.nickName = nickName;
    }

    public String getProfileUrl() {
        return profileUrl;
    }

    public void setProfileUrl(String profileUrl) {
        this.profileUrl = profileUrl;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getUserType() {
        return userType;
    }

    public void setUserType(String userType) {
        this.userType = userType;
    }

    public String getPreferredLanguage() {
        return preferredLanguage;
    }

    public void setPreferredLanguage(String preferredLanguage) {
        this.preferredLanguage = preferredLanguage;
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public String getTimezone() {
        return timezone;
    }

    public void setTimezone(String timezone) {
        this.timezone = timezone;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public String getExternalId() {
        return externalId;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public String getZoneId() {
        return zoneId;
    }

    public void setZoneId(String zoneId) {
        this.zoneId = zoneId;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    @JsonIgnore
    public String getPrimaryEmail() {
        if (getEmails() == null || getEmails().isEmpty()) {
            return null;
        }

        Email primaryEmail = null;

        for (Email email : getEmails()) {
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

    public void setPrimaryEmail(String value) {
        Email newPrimaryEmail = new Email();
        newPrimaryEmail.setPrimary(true);
        newPrimaryEmail.setValue(value);

        if (emails == null) {
            emails = new ArrayList<>(1);
        }
        else {
            emails = new ArrayList<>(getEmails());
        }

        Email currentPrimaryEmail = null;
        for (Email email : emails) {
            if (email.isPrimary()) {
                currentPrimaryEmail = email;
                break;
            }
        }
        if (currentPrimaryEmail != null) {
            emails.remove(currentPrimaryEmail);
        }
        emails.add(0, newPrimaryEmail);
    }

    @JsonIgnore
    public String getGivenName() {
        return name == null ? null : name.getGivenName();
    }

    @JsonIgnore
    public String getFamilyName() {
        return name == null ? null : name.getFamilyName();
    }

    /**
     * Adds a new email address, ignoring "type" and "primary" fields, which we
     * don't need yet
     */
    public void addEmail(String newEmail) {
        Assert.hasText(newEmail);

        if (emails == null) {
            emails = new ArrayList<>(1);
        }
        for (Email email : emails) {
            if (email.value.equals(newEmail)) {
                throw new IllegalArgumentException("Already contains email " + newEmail);
            }
        }

        Email e = new Email();
        e.setValue(newEmail);
        emails.add(e);
    }

    /**
     * Adds a new phone number with null type.
     *
     * @param newPhoneNumber
     */
    public void addPhoneNumber(String newPhoneNumber) {
        if (newPhoneNumber==null || newPhoneNumber.trim().length()==0) {
            return;
        }

        if (phoneNumbers == null) {
            phoneNumbers = new ArrayList<PhoneNumber>(1);
        }
        for (PhoneNumber phoneNumber : phoneNumbers) {
            if (phoneNumber.value.equals(newPhoneNumber) && phoneNumber.getType() == null) {
                throw new IllegalArgumentException("Already contains phoneNumber " + newPhoneNumber);
            }
        }

        PhoneNumber number = new PhoneNumber();
        number.setValue(newPhoneNumber);
        phoneNumbers.add(number);
    }

    /**
     * Creates a word list from the user data for use in password checking
     * implementations
     */
    public List<String> wordList() {
        List<String> words = new ArrayList<String>();

        if (userName != null) {
            words.add(userName);
        }

        if (name != null) {
            if (name.givenName != null) {
                words.add(name.givenName);
            }
            if (name.familyName != null) {
                words.add(name.familyName);
            }
            if (nickName != null) {
                words.add(nickName);
            }
        }

        if (emails != null) {
            for (Email email : emails) {
                words.add(email.getValue());
            }
        }

        return words;
    }

}
