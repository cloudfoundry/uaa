
package org.cloudfoundry.identity.uaa.resources;

import java.util.List;

public interface ResourceManager<T> {

    List<T> retrieveAll(String zoneId);

    T retrieve(String id, String zoneId);

    T create(T resource, String zoneId);

    T update(String id, T resource, String zoneId);

    T delete(String id, int version, String zoneId);

}
