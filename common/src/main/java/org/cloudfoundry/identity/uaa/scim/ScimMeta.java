package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.util.json.JsonDateDeserializer;
import org.cloudfoundry.identity.uaa.util.json.JsonDateSerializer;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;

import java.util.Date;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class ScimMeta {
	private int version = 0;

	private Date created = new Date();

	private Date lastModified = null;

	public ScimMeta() {
	}

	public ScimMeta(Date created, Date lastModified, int version) {
		this.created = created;
		this.lastModified = lastModified;
		this.version = version;
	}

	@JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
	public Date getCreated() {
		return created;
	}

	@JsonDeserialize(using = JsonDateDeserializer.class)
	public void setCreated(Date created) {
		this.created = created;
	}

	@JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
	public Date getLastModified() {
		return lastModified;
	}

	@JsonDeserialize(using = JsonDateDeserializer.class)
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