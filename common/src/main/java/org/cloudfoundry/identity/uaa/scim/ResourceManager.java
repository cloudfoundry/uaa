package org.cloudfoundry.identity.uaa.scim;

import java.util.List;

public interface ResourceManager<T> {

	List<T> retrieveAll();

	T retrieve (String id);

	T create (T resource);

	T update (String id, T resource);

	T delete (String id, int version);

}
