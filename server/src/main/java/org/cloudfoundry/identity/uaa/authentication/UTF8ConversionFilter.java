package org.cloudfoundry.identity.uaa.authentication;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.ISO_8859_1;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.convertISO8859_1_to_UTF_8;
import static org.springframework.util.StringUtils.hasText;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

public class UTF8ConversionFilter implements Filter {

  public static final String NULL_STRING = new String(new char[] {'\u0000'});

  @Override
  public void init(FilterConfig filterConfig) {}

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;
    // application/x-www-form-urlencoded is always considered ISO-8859-1 by tomcat even when
    // because there is no charset defined
    // the browser sends up UTF-8
    // https://www.w3.org/TR/html5/forms.html#application/x-www-form-urlencoded-encoding-algorithm
    if (MediaType.APPLICATION_FORM_URLENCODED_VALUE.equals(request.getContentType())
        && (request.getCharacterEncoding() == null
            || ISO_8859_1.equalsIgnoreCase(request.getCharacterEncoding()))) {
      request = new UtfConverterRequestWrapper(request);
    }
    validateParamsAndContinue(request, response, chain);
  }

  protected void validateParamsAndContinue(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    for (Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
      if (entry.getValue() != null && entry.getValue().length > 0) {
        for (String s : entry.getValue()) {
          if (hasText(s) && s.contains(NULL_STRING)) {
            response.setStatus(400);
            request.setAttribute("error_message_code", "request.invalid_parameter");
            request.getRequestDispatcher("/error").forward(request, response);
            return;
          }
        }
      }
    }
    chain.doFilter(request, response);
  }

  @Override
  public void destroy() {}

  public static class UtfConverterRequestWrapper extends HttpServletRequestWrapper {

    public UtfConverterRequestWrapper(HttpServletRequest request) {
      super(request);
    }

    @Override
    public String getParameter(String name) {
      return convertISO8859_1_to_UTF_8(super.getParameter(name));
    }

    @Override
    public String[] getParameterValues(String name) {
      String[] values = super.getParameterValues(name);
      if (values == null || values.length == 0) {
        return values;
      }
      String[] result = new String[values.length];
      for (int i = 0; i < result.length; i++) {
        result[i] = convertISO8859_1_to_UTF_8(values[i]);
      }
      return result;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
      Map<String, String[]> map = new HashMap<>();
      Enumeration<String> names = getParameterNames();

      while (names.hasMoreElements()) {
        String name = names.nextElement();
        map.put(name, getParameterValues(name));
      }
      return map;
    }
  }
}
