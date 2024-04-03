package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.io.Serializable;
import java.util.Objects;

public class DefaultOAuth2RefreshToken implements Serializable, OAuth2RefreshToken {

	private static final long serialVersionUID = 8349970621900575838L;

	private String value;

	/**
	 * Create a new refresh token.
	 */
	@JsonCreator
	public DefaultOAuth2RefreshToken(String value) {
		this.value = value;
	}
	
	/**
	 * Default constructor for JPA and other serialization tools.
	 */
	@SuppressWarnings("unused")
	private DefaultOAuth2RefreshToken() {
		this(null);
	}

	/* (non-Javadoc)
	 * @see IFOO#getValue()
	 */
	@JsonValue
	public String getValue() {
		return value;
	}

	@Override
	public String toString() {
		return getValue();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof DefaultOAuth2RefreshToken)) {
			return false;
		}

		DefaultOAuth2RefreshToken that = (DefaultOAuth2RefreshToken) o;

		return Objects.equals(value, that.value);
	}

	@Override
	public int hashCode() {
		return value != null ? value.hashCode() : 0;
	}
}
