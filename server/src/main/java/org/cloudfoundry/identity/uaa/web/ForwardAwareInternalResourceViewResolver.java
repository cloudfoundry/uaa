package org.cloudfoundry.identity.uaa.web;

import java.util.List;
import java.util.Locale;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.AbstractView;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

/** @author Dave Syer */
public class ForwardAwareInternalResourceViewResolver extends InternalResourceViewResolver {

  private static final String ACCEPT_HEADER = "Accept";

  @Override
  protected Object getCacheKey(String viewName, Locale locale) {
    return super.getCacheKey(viewName + ";" + getRequestedMediaType(), locale);
  }

  @Override
  protected View createView(String viewName, Locale locale) throws Exception {
    View view = super.createView(viewName, locale);
    if (viewName.startsWith(FORWARD_URL_PREFIX) || viewName.startsWith(REDIRECT_URL_PREFIX)) {
      if (view instanceof AbstractView) {
        MediaType requestedMediaType = getRequestedMediaType();
        if (requestedMediaType != null) {
          ((AbstractView) view).setContentType(requestedMediaType.toString());
        }
      }
    }
    return view;
  }

  private MediaType getRequestedMediaType() {
    RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
    Assert.isInstanceOf(ServletRequestAttributes.class, attrs);
    HttpServletRequest request = ((ServletRequestAttributes) attrs).getRequest();
    return getMediaTypes(request);
  }

  private MediaType getMediaTypes(HttpServletRequest request) {
    String acceptHeader = request.getHeader(ACCEPT_HEADER);
    if (StringUtils.hasText(acceptHeader)) {
      try {
        List<MediaType> acceptableMediaTypes = MediaType.parseMediaTypes(acceptHeader);
        return acceptableMediaTypes.isEmpty() ? null : acceptableMediaTypes.get(0);
      } catch (IllegalArgumentException ex) {
        if (logger.isDebugEnabled()) {
          logger.debug("Could not parse accept header [" + acceptHeader + "]: " + ex.getMessage());
        }
        return null;
      }
    }
    return null;
  }
}
