package org.cloudfoundry.identity.uaa.web;

import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;
import static java.util.Optional.ofNullable;

import java.io.IOException;
import java.util.List;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class HeaderFilter implements Filter {

  private final List<String> filteredHeaderNames;

  public HeaderFilter(List<String> filteredHeaderNames) {
    this.filteredHeaderNames =
        unmodifiableList(ofNullable(filteredHeaderNames).orElse(emptyList()));
  }

  public List<String> getFilteredHeaderNames() {
    return filteredHeaderNames;
  }

  @Override
  public void init(FilterConfig filterConfig) {}

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    chain.doFilter(
        new HttpHeadersFilterRequestWrapper(filteredHeaderNames, (HttpServletRequest) request),
        response);
  }

  @Override
  public void destroy() {}
}
