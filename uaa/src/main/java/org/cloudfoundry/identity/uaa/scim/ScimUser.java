package org.cloudfoundry.identity.uaa.scim;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Object to hold SCIM data for Jackson to map to and from JSON
 *
 * See the <a href="http://www.simplecloud.info/specs/draft-scim-core-schema-02.html">SCIM user schema</a>.
 *
 * @author Luke Taylor
 */
@JsonSerialize (include = JsonSerialize.Inclusion.NON_NULL)
public final class ScimUser {
	private static final String[] SCHEMAS = new String[] {"urn:scim:schemas:core:1.0"};
	@JsonSerialize (include = JsonSerialize.Inclusion.NON_NULL)
	public static final class Name {
		String formatted;
		String familyName;
		String givenName;
		String middleName;
		String honorificPrefix;
		String honorificSuffix;

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

	@JsonSerialize (include = JsonSerialize.Inclusion.NON_NULL)
	public static final class Email {
		private String value;
		// this should probably be an enum
		private String type;
		private Boolean primary;

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

		public Boolean getPrimary() {
			return primary;
		}

		public void setPrimary(boolean primary) {
			this.primary = primary;
		}

		@JsonIgnore
		public boolean isPrimary() {
			return primary != null && primary;
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
	private String title;
	private String userType;
	private String preferredLanguage;
	private String locale;
	private String timezone;
	private Boolean active;

	public ScimUser() {
	}

	public ScimUser(String id) {
		this.id = id;
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

	public Boolean getActive() {
		return active;
	}

	public void setActive(boolean active) {
		this.active = active;
	}

	public void setSchemas(String[] schemas) {
		Assert.isTrue(Arrays.equals(SCHEMAS, schemas), "Only schema '" + SCHEMAS[0] + "' is currently supported");
	}

	public String[] getSchemas() {
		return SCHEMAS;
	}

	@JsonIgnore
	public Email getPrimaryEmail() {
		Email primaryEmail = null;

		for (Email email : getEmails()) {
			if (email.isPrimary()) {
				primaryEmail = email;
				break;
			}
		}

		// Assuming emails can't be empty
		if (primaryEmail == null) {
			primaryEmail = getEmails().get(0);
		}

		return primaryEmail;
	}

	/**
	 * Adds a new email address, ignoring "type" and "primary" fields, which we don't need yet
	 */
	public void addEmail(String newEmail) {
		if (emails == null) {
			emails = new ArrayList<Email>();
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

}
