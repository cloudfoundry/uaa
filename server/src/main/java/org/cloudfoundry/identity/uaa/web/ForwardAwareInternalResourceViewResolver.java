/*
 * *****************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.web;

import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.AbstractView;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Locale;

/**
 * @author Dave Syer
 * 
 */
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
            if (view instanceof AbstractView abstractView) {
                MediaType requestedMediaType = getRequestedMediaType();
                if (requestedMediaType != null) {
                    abstractView.setContentType(requestedMediaType.toString());
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
                return acceptableMediaTypes.isEmpty() ? null : acceptableMediaTypes.getFirst();
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
