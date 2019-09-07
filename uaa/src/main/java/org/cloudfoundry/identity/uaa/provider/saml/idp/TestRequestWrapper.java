/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml.idp;

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

public class TestRequestWrapper extends HttpServletRequestWrapper {

    public TestRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    @Override
    public String getAuthType() {
        return super.getAuthType();
    }

    @Override
    public Cookie[] getCookies() {
        return super.getCookies();
    }

    @Override
    public long getDateHeader(String name) {
        return super.getDateHeader(name);
    }

    @Override
    public String getHeader(String name) {
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        return super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        return super.getHeaderNames();
    }

    @Override
    public int getIntHeader(String name) {
        return super.getIntHeader(name);
    }

    @Override
    public String getMethod() {
        return super.getMethod();
    }

    @Override
    public String getPathInfo() {
        return super.getPathInfo();
    }

    @Override
    public String getPathTranslated() {
        return super.getPathTranslated();
    }

    @Override
    public String getContextPath() {
        return super.getContextPath();
    }

    @Override
    public String getQueryString() {
        return super.getQueryString();
    }

    @Override
    public String getRemoteUser() {
        return super.getRemoteUser();
    }

    @Override
    public boolean isUserInRole(String role) {
        return super.isUserInRole(role);
    }

    @Override
    public Principal getUserPrincipal() {
        return super.getUserPrincipal();
    }

    @Override
    public String getRequestedSessionId() {
        return super.getRequestedSessionId();
    }

    @Override
    public String getRequestURI() {
        return super.getRequestURI();
    }

    @Override
    public StringBuffer getRequestURL() {
        return super.getRequestURL();
    }

    @Override
    public String getServletPath() {
        return super.getServletPath();
    }

    @Override
    public HttpSession getSession(boolean create) {
        return super.getSession(create);
    }

    @Override
    public HttpSession getSession() {
        return super.getSession();
    }

    @Override
    public String changeSessionId() {
        return super.changeSessionId();
    }

    @Override
    public boolean isRequestedSessionIdValid() {
        return super.isRequestedSessionIdValid();
    }

    @Override
    public boolean isRequestedSessionIdFromCookie() {
        return super.isRequestedSessionIdFromCookie();
    }

    @Override
    public boolean isRequestedSessionIdFromURL() {
        return super.isRequestedSessionIdFromURL();
    }

    @Override
    public boolean isRequestedSessionIdFromUrl() {
        return super.isRequestedSessionIdFromUrl();
    }

    @Override
    public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
        return super.authenticate(response);
    }

    @Override
    public void login(String username, String password) throws ServletException {
        super.login(username, password);
    }

    @Override
    public void logout() throws ServletException {
        super.logout();
    }

    @Override
    public Collection<Part> getParts() throws IOException, ServletException {
        return super.getParts();
    }

    @Override
    public Part getPart(String name) throws IOException, ServletException {
        return super.getPart(name);
    }

    @Override
    public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass) throws IOException, ServletException {
        return super.upgrade(handlerClass);
    }

    @Override
    public ServletRequest getRequest() {
        return super.getRequest();
    }

    @Override
    public void setRequest(ServletRequest request) {
        super.setRequest(request);
    }

    @Override
    public Object getAttribute(String name) {
        return super.getAttribute(name);
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        return super.getAttributeNames();
    }

    @Override
    public String getCharacterEncoding() {
        return super.getCharacterEncoding();
    }

    @Override
    public void setCharacterEncoding(String enc) throws UnsupportedEncodingException {
        super.setCharacterEncoding(enc);
    }

    @Override
    public int getContentLength() {
        return super.getContentLength();
    }

    @Override
    public long getContentLengthLong() {
        return super.getContentLengthLong();
    }

    @Override
    public String getContentType() {
        return super.getContentType();
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return super.getInputStream();
    }

    @Override
    public String getParameter(String name) {
        return super.getParameter(name);
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return super.getParameterMap();
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return super.getParameterNames();
    }

    @Override
    public String[] getParameterValues(String name) {
        return super.getParameterValues(name);
    }

    @Override
    public String getProtocol() {
        return super.getProtocol();
    }

    @Override
    public String getScheme() {
        return super.getScheme();
    }

    @Override
    public String getServerName() {
        return super.getServerName();
    }

    @Override
    public int getServerPort() {
        return super.getServerPort();
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return super.getReader();
    }

    @Override
    public String getRemoteAddr() {
        return super.getRemoteAddr();
    }

    @Override
    public String getRemoteHost() {
        return super.getRemoteHost();
    }

    @Override
    public void setAttribute(String name, Object o) {
        super.setAttribute(name, o);
    }

    @Override
    public void removeAttribute(String name) {
        super.removeAttribute(name);
    }

    @Override
    public Locale getLocale() {
        return super.getLocale();
    }

    @Override
    public Enumeration<Locale> getLocales() {
        return super.getLocales();
    }

    @Override
    public boolean isSecure() {
        return super.isSecure();
    }

    @Override
    public RequestDispatcher getRequestDispatcher(String path) {
        return super.getRequestDispatcher(path);
    }

    @Override
    public String getRealPath(String path) {
        return super.getRealPath(path);
    }

    @Override
    public int getRemotePort() {
        return super.getRemotePort();
    }

    @Override
    public String getLocalName() {
        return super.getLocalName();
    }

    @Override
    public String getLocalAddr() {
        return super.getLocalAddr();
    }

    @Override
    public int getLocalPort() {
        return super.getLocalPort();
    }

    @Override
    public ServletContext getServletContext() {
        return super.getServletContext();
    }

    @Override
    public AsyncContext startAsync() throws IllegalStateException {
        return super.startAsync();
    }

    @Override
    public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException {
        return super.startAsync(servletRequest, servletResponse);
    }

    @Override
    public boolean isAsyncStarted() {
        return super.isAsyncStarted();
    }

    @Override
    public boolean isAsyncSupported() {
        return super.isAsyncSupported();
    }

    @Override
    public AsyncContext getAsyncContext() {
        return super.getAsyncContext();
    }

    @Override
    public boolean isWrapperFor(ServletRequest wrapped) {
        return super.isWrapperFor(wrapped);
    }

    @Override
    public boolean isWrapperFor(Class<?> wrappedType) {
        return super.isWrapperFor(wrappedType);
    }

    @Override
    public DispatcherType getDispatcherType() {
        return super.getDispatcherType();
    }
}
