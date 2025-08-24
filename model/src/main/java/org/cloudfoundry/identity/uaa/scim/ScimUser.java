/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.cloudfoundry.identity.uaa.EntityWithAlias;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.impl.JsonDateSerializer;
import org.cloudfoundry.identity.uaa.scim.impl.ScimUserJsonDeserializer;
import org.springframework.lang.NonNull;
import org.springframework.util.Assert;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import lombok.Setter;

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
public class ScimUser extends ScimCore<ScimUser> implements EntityWithAlias {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Group {
        String value;

        String display;

        public enum Type {
            DIRECT, INDIRECT
        }

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
            result = prime * result + (display == null ? 0 : display.hashCode());
            result = prime * result + (value == null ? 0 : value.hashCode());
            result = prime * result + (type == null ? 0 : type.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            Group other = (Group) obj;
            if (display == null) {
                if (other.display != null) {
                    return false;
                }
            } else if (!display.equals(other.display)) {
                return false;
            }
            if (value == null) {
                if (other.value != null) {
                    return false;
                }
            } else if (!value.equals(other.value)) {
                return false;
            }
            return type == other.type;
        }

        @Override
        public String toString() {
            return "(id: %s, name: %s, type: %s)".formatted(value, display, type);
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

        String getMiddleName() {
            return middleName;
        }

        void setMiddleName(String middleName) {
            this.middleName = middleName;
        }

        String getHonorificPrefix() {
            return honorificPrefix;
        }

        void setHonorificPrefix(String honorificPrefix) {
            this.honorificPrefix = honorificPrefix;
        }

        String getHonorificSuffix() {
            return honorificSuffix;
        }

        void setHonorificSuffix(String honorificSuffix) {
            this.honorificSuffix = honorificSuffix;
        }

    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Email {
        private String value;

        // this should probably be an enum
        private String type;

        private boolean primary;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            Assert.notNull(value, "must not be null");
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
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            Email email = (Email) o;

            if (primary != email.primary) {
                return false;
            }
            if (!Objects.equals(type, email.type)) {
                return false;
            }
            return Objects.equals(value, email.value);
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

        public PhoneNumber(String phoneNumber) {
            this.value = phoneNumber;
        }

        public PhoneNumber() {
        }

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

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            PhoneNumber that = (PhoneNumber) o;
            return Objects.equals(value, that.value) &&
                    Objects.equals(type, that.type);
        }

        @Override
        public int hashCode() {
            return Objects.hash(value, type);
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

    private String title;

    private String userType;

    private String preferredLanguage;

    private String locale;

    private String timezone;

    private boolean active = true;

    private boolean verified = true;

    private String origin = "";

    private String externalId = "";

    private String zoneId;

    @Setter
    private String aliasZid;

    @Setter
    private String aliasId;

    private String salt;

    private Date passwordLastModified;

    private Long previousLogonTime;

    private Long lastLogonTime;

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

    public void setGroups(@NonNull Collection<Group> groups) {
        this.groups = new LinkedHashSet<>(groups);
    }

    public List<PhoneNumber> getPhoneNumbers() {
        return phoneNumbers;
    }

    public void setPhoneNumbers(List<PhoneNumber> phoneNumbers) {
        if (phoneNumbers != null && !phoneNumbers.isEmpty()) {
            ArrayList<PhoneNumber> list = new ArrayList<>(phoneNumbers);
            for (int i = list.size() - 1; i >= 0; i--) {
                PhoneNumber pn = list.get(i);
                if (pn == null || (!hasText(pn.getValue()))) {
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

    String getNickName() {
        return nickName;
    }

    public void setNickName(String nickName) {
        this.nickName = nickName;
    }

    String getProfileUrl() {
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

    String getPreferredLanguage() {
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

    String getTimezone() {
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

    @Override
    public String getExternalId() {
        return externalId;
    }

    @Override
    public ScimUser setExternalId(String externalId) {
        this.externalId = externalId;
        return this;
    }

    @Override
    public String getZoneId() {
        return zoneId;
    }

    public void setZoneId(String zoneId) {
        this.zoneId = zoneId;
    }

    @Override
    public String getAliasId() {
        return aliasId;
    }

    @Override
    public String getAliasZid() {
        return aliasZid;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    @JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
    public Date getPasswordLastModified() {
        if (passwordLastModified != null) {
            return passwordLastModified;
        } else if (getId() != null) {
            return getMeta().getCreated();
        }
        return null;
    }

    public void setPasswordLastModified(Date passwordLastModified) {
        this.passwordLastModified = passwordLastModified;
    }

    public Long getLastLogonTime() {
        return lastLogonTime;
    }

    public void setLastLogonTime(Long lastLogonTime) {
        this.lastLogonTime = lastLogonTime;
    }

    public Long getPreviousLogonTime() {
        return previousLogonTime;
    }

    public void setPreviousLogonTime(Long previousLogonTime) {
        this.previousLogonTime = previousLogonTime;
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
            primaryEmail = getEmails().getFirst();
        }

        return primaryEmail.getValue();
    }

    public void setPrimaryEmail(String value) {
        Assert.notNull(value, "must not be null");

        Email newPrimaryEmail = new Email();
        newPrimaryEmail.setPrimary(true);
        newPrimaryEmail.setValue(value);

        if (emails == null) {
            emails = new ArrayList<>(1);
        } else {
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
        emails.addFirst(newPrimaryEmail);
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
        Assert.hasText(newEmail, "Attempted to add null or empty email string to user.");

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
     */
    public void addPhoneNumber(String newPhoneNumber) {
        if (newPhoneNumber == null || newPhoneNumber.trim().isEmpty()) {
            return;
        }

        if (phoneNumbers == null) {
            phoneNumbers = new ArrayList<>(1);
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
    List<String> wordList() {
        List<String> words = new ArrayList<>();

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

    @Override
    public void patch(ScimUser patch) {
        //Delete Attributes specified in Meta.attributes
        String[] attributes = ofNullable(patch.getMeta().getAttributes()).orElse(new String[0]);
        removeAttributesForPatch(patch, attributes);

        if (hasText(patch.getOrigin()) && !patch.getOrigin().equals(getOrigin())) {
            throw new IllegalArgumentException("Cannot change origin in patch of user.");
        }

        //Merge simple Attributes, that are stored
        ofNullable(patch.getUserName()).ifPresent(this::setUserName);

        setActive(patch.isActive());
        setVerified(patch.isVerified());

        //Merge complex attributes
        ScimUser.Name patchName = patch.getName();
        if (patchName != null) {
            patchName(patchName);
        }

        ofNullable(patch.getDisplayName()).ifPresent(
                this::setDisplayName
        );
        ofNullable(patch.getNickName()).ifPresent(this::setNickName);
        ofNullable(patch.getTimezone()).ifPresent(this::setTimezone);
        ofNullable(patch.getTitle()).ifPresent(this::setTitle);
        ofNullable(patch.getProfileUrl()).ifPresent(this::setProfileUrl);
        ofNullable(patch.getLocale()).ifPresent(this::setLocale);
        ofNullable(patch.getPreferredLanguage()).ifPresent(this::setPreferredLanguage);

        //Only one email stored, use Primary or first.
        if (patch.getEmails() != null && !patch.getEmails().isEmpty()) {
            ScimUser.Email primary = null;
            for (ScimUser.Email email : patch.getEmails()) {
                if (email.isPrimary()) {
                    primary = email;
                    break;
                }
            }
            List<Email> currentEmails = ofNullable(getEmails()).orElse(new ArrayList<>());
            if (primary != null) {
                for (Email e : currentEmails) {
                    e.setPrimary(false);
                }
            }
            currentEmails.addAll(patch.getEmails());
            setEmails(currentEmails);
        }

        //Only one PhoneNumber stored, use first, as primary does not exist
        if (patch.getPhoneNumbers() != null && !patch.getPhoneNumbers().isEmpty()) {
            List<PhoneNumber> current = ofNullable(getPhoneNumbers()).orElse(new ArrayList<>());
            for (int index = 0; index < patch.getPhoneNumbers().size(); index++) {
                current.add(index, patch.getPhoneNumbers().get(index));
            }
            setPhoneNumbers(current);
        }

        ofNullable(patch.getAliasId()).ifPresent(this::setAliasId);
        ofNullable(patch.getAliasZid()).ifPresent(this::setAliasZid);
    }

    private void removeAttributesForPatch(final ScimUser patch, final String[] attributes) {
        for (String attribute : attributes) {
            switch (attribute.toUpperCase()) {
                case "USERNAME":
                    if (!hasText(patch.getUserName())) {
                        throw new IllegalArgumentException("Can not drop username, field is required.");
                    }
                    setUserName(null);
                    break;
                case "EMAILS":
                    setEmails(new ArrayList<>());
                    break;
                case "PHONENUMBERS":
                    setPhoneNumbers(new ArrayList<>());
                    break;
                case "DISPLAYNAME":
                    setDisplayName(null);
                    break;
                case "NICKNAME":
                    setNickName(null);
                    break;
                case "PROFILEURL":
                    setProfileUrl(null);
                    break;
                case "TITLE":
                    setTitle(null);
                    break;
                case "PREFERREDLANGUAGE":
                    setPreferredLanguage(null);
                    break;
                case "LOCALE":
                    setLocale(null);
                    break;
                case "TIMEZONE":
                    setTimezone(null);
                    break;
                case "NAME":
                    setName(new Name());
                    break;
                case "NAME.FAMILYNAME":
                    ofNullable(getName()).ifPresent(n -> n.setFamilyName(null));
                    break;
                case "NAME.GIVENNAME":
                    ofNullable(getName()).ifPresent(n -> n.setGivenName(null));
                    break;
                case "NAME.FORMATTED":
                    ofNullable(getName()).ifPresent(n -> n.setFormatted(null));
                    break;
                case "NAME.HONORIFICPREFIX":
                    ofNullable(getName()).ifPresent(n -> n.setHonorificPrefix(null));
                    break;
                case "NAME.HONORIFICSUFFIX":
                    ofNullable(getName()).ifPresent(n -> n.setHonorificSuffix(null));
                    break;
                case "NAME.MIDDLENAME":
                    ofNullable(getName()).ifPresent(n -> n.setMiddleName(null));
                    break;
                default:
                    throw new IllegalArgumentException("Attribute %s cannot be removed using \"Meta.attributes\"".formatted(attribute));
            }
        }
    }

    private void patchName(@NonNull final Name patchName) {
        Name currentName = ofNullable(getName()).orElse(new Name());
        ofNullable(patchName.getFamilyName()).ifPresent(currentName::setFamilyName);
        ofNullable(patchName.getGivenName()).ifPresent(currentName::setGivenName);
        ofNullable(patchName.getMiddleName()).ifPresent(currentName::setMiddleName);
        ofNullable(patchName.getFormatted()).ifPresent(currentName::setFormatted);
        ofNullable(patchName.getHonorificPrefix()).ifPresent(currentName::setHonorificPrefix);
        ofNullable(patchName.getHonorificSuffix()).ifPresent(currentName::setHonorificSuffix);
        setName(currentName);
    }
}
