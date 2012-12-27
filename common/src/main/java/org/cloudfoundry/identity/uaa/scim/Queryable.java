package org.cloudfoundry.identity.uaa.scim;

import java.util.List;

public interface Queryable<T> {

	List<T> query (String filter);

	List<T> query (String filter, String sortBy, boolean ascending);

}
