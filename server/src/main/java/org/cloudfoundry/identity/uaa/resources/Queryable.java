package org.cloudfoundry.identity.uaa.resources;

import java.util.List;

public interface Queryable<T> {

  List<T> query(String filter, String zoneId);

  List<T> query(String filter, String sortBy, boolean ascending, String zoneId);
}
