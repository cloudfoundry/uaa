package org.cloudfoundry.identity.uaa.resources;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * SearchResults.
 *
 * @author Dave Syer.
 */
public class SearchResults<T> {

  private List<T> resources;
  private int startIndex;
  private int itemsPerPage;
  private int totalResults;
  private Collection<String> schemas;

  public SearchResults() {
  }

  public SearchResults(
      Collection<String> schemas,
      Collection<T> resources,
      int startIndex,
      int itemsPerPage,
      int totalResults) {
    this.schemas = new ArrayList<String>(schemas);
    this.resources = new ArrayList<T>(resources);
    this.startIndex = startIndex;
    this.itemsPerPage = itemsPerPage;
    this.totalResults = totalResults;
  }

  public Collection<String> getSchemas() {
    return schemas;
  }

  public int getStartIndex() {
    return startIndex;
  }

  public int getItemsPerPage() {
    return itemsPerPage;
  }

  public int getTotalResults() {
    return totalResults;
  }

  public List<T> getResources() {
    return resources;
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder("SearchResults[schemas:");
    builder.append(getSchemas());
    builder.append("; count:");
    builder.append(getTotalResults());
    builder.append("; size:");
    builder.append(getResources().size());
    builder.append("; index:");
    builder.append(getStartIndex());
    builder.append("; resources:");
    builder.append(getResources());
    builder.append("; id:");
    builder.append(System.identityHashCode(this));
    builder.append(";]");
    return builder.toString();
  }
}
