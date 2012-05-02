/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.scim;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.cloudfoundry.identity.uaa.scim.json.JsonDateDeserializer;
import org.cloudfoundry.identity.uaa.scim.json.JsonDateSerializer;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.springframework.util.Assert;

/**
 * Object to hold SCIM data for Jackson to map to and from JSON
 *
 * See the <a href="http://www.simplecloud.info/specs/draft-scim-core-schema-02.html">SCIM user schema</a>.
 *
 * @author Luke Taylor
 */
@JsonSerialize (include = JsonSerialize.Inclusion.NON_NULL)
public final class ScimUser {

	public static final String[] SCHEMAS = new String[] {"urn:scim:schemas:core:1.0"};

	@JsonSerialize (include = JsonSerialize.Inclusion.NON_NULL)
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

	@JsonSerialize (include = JsonSerialize.Inclusion.NON_DEFAULT)
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
	}

	@JsonSerialize (include = JsonSerialize.Inclusion.NON_NULL)
	public static final class Meta {
		private int version = 0;
		private Date created = new Date();
		private Date lastModified = null;

		public Meta() {
		}

		public Meta(Date created, Date lastModified, int version) {
			this.created = created;
			this.lastModified = lastModified;
			this.version = version;
		}

		@JsonSerialize(using=JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
		public Date getCreated() {
			return created;
		}

		@JsonDeserialize(using=JsonDateDeserializer.class)
		public void setCreated(Date created) {
			this.created = created;
		}

		@JsonSerialize(using=JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
		public Date getLastModified() {
			return lastModified;
		}

		@JsonDeserialize(using=JsonDateDeserializer.class)
		public void setLastModified(Date lastModified) {
			this.lastModified = lastModified;
		}

		public void setVersion(int version) {
			this.version = version;
		}

		public int getVersion() {
			return version;
		}
	}

	private String id;
	private String externalId;
	private String userName;
	private Name name;
	private List<Email> emails;
	private String displayName;
	private String nickName;
	private String profileUrl;
	private String title;;
	private String userType;
	private String preferredLanguage;
	private String locale;
	private String timezone;
	private boolean active = true;
	private Meta meta = new Meta();
	@JsonProperty
	private String password;

	public ScimUser() {
	}

	public ScimUser(String id, String userName, String givenName, String familyName) {
		this.id = id;
		setUserName(userName);
		this.name = new Name(givenName, familyName);
	}

	public String getId() {
		return id;
	}

	void setId(String id) {
		this.id = id;
	}

	public String getExternalId() {
		return externalId;
	}

	public void setExternalId(String externalId) {
		this.externalId = externalId;
	}

	public String getUserName() {
		return userName;
	}

	public String getPassword() {
		return password;
	}
	
	protected void setPassword(String password) {
		this.password = password;
	}

	public void setUserName(String userName) {
		this.userName = userName.toLowerCase();
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

	public Meta getMeta() {
		return meta;
	}

	public void setMeta(Meta meta) {
		this.meta = meta;
	}

	@JsonIgnore
	public void setVersion(int version) {
		meta.setVersion(version);
	}

	@JsonIgnore
	public int getVersion() {
		return meta.getVersion();
	}

	public void setSchemas(String[] schemas) {
		Assert.isTrue(Arrays.equals(SCHEMAS, schemas), "Only schema '" + SCHEMAS[0] + "' is currently supported");
	}

	public String[] getSchemas() {
		return SCHEMAS;
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

	@JsonIgnore
	public String getGivenName() {
		return name == null ? null : name.getGivenName();
	}

	@JsonIgnore
	public String getFamilyName() {
		return name == null ? null : name.getFamilyName();
	}

	/**
	 * Adds a new email address, ignoring "type" and "primary" fields, which we don't need yet
	 */
	public void addEmail(String newEmail) {
		Assert.hasText(newEmail);

		if (emails == null) {
			emails = new ArrayList<Email>(1);
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
	 * Creates a word list from the user data for use in password checking implementations
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
