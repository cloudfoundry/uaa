package org.cloudfoundry.identity.uaa.web;

import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;
import static java.util.Optional.ofNullable;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import org.cloudfoundry.identity.uaa.util.EmptyEnumerationOfString;

public class HttpHeadersFilterRequestWrapper extends HttpServletRequestWrapper {

  private final List<String> filteredHeaders;

  public HttpHeadersFilterRequestWrapper(List<String> badHeaders, HttpServletRequest request) {
    super(request);
    this.filteredHeaders = unmodifiableList(ofNullable(badHeaders).orElse(emptyList()));
  }

  @Override
  public String getHeader(String name) {
    if (shouldFilter(name)) {
      return null;
    }
    return super.getHeader(name);
  }

  @Override
  public Enumeration<String> getHeaders(String name) {
    if (shouldFilter(name)) {
      return EmptyEnumerationOfString.EMPTY_ENUMERATION;
    }
    return super.getHeaders(name);
  }

  private boolean shouldFilter(String name) {
    return filteredHeaders.stream().anyMatch(s -> s.equalsIgnoreCase(name));
  }

  @Override
  public Enumeration<String> getHeaderNames() {
    List<String> headerNames = Collections.list(super.getHeaderNames());
    headerNames.removeIf(header -> shouldFilter(header));
    return Collections.enumeration(headerNames);
  }
}
