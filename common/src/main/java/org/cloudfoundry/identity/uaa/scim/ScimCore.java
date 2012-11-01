package org.cloudfoundry.identity.uaa.scim;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.springframework.util.Assert;

import java.util.Arrays;

public abstract class ScimCore {

	public static final String[] SCHEMAS = new String[]{"urn:scim:schemas:core:1.0"};

	private String id;

	private String externalId;

	private ScimMeta meta = new ScimMeta();

	protected ScimCore(String id) {
		this.id = id;
	}

	protected ScimCore() {
	}

	public void setSchemas(String[] schemas) {
		Assert.isTrue(Arrays.equals(SCHEMAS, schemas), "Only schema '" + SCHEMAS[0] + "' is currently supported");
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getExternalId() {
		return externalId;
	}

	public void setExternalId(String externalId) {
		this.externalId = externalId;
	}

	public ScimMeta getMeta() {
		return meta;
	}

	public void setMeta(ScimMeta meta) {
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

	public String[] getSchemas() {
		return SCHEMAS;
	}

	@Override
	public int hashCode() {
		return id != null ? id.hashCode() : super.hashCode();
	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof ScimCore) {
			ScimCore other = (ScimCore) o;
			return id.equals(other.id);
		} else if (o instanceof String) {
			String otherId = (String) o;
			return id.equals(otherId);
		}
		return false;
	}
}
