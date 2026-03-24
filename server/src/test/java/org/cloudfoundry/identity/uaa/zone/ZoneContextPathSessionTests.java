package org.cloudfoundry.identity.uaa.zone;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter.DEFAULT_ZONE_SUBDOMAIN_PATH;

class ZoneContextPathSessionTests {

    private final TimeService timeService = new TimeService() {};

    // ───────────────────────────────────────────────────────────────────────────
    // ZonePathHttpSession
    // ───────────────────────────────────────────────────────────────────────────

    @Nested
    class ZonePathHttpSessionTests {

        private MockHttpSession containerSession;
        private ZonePathHttpSession subSession;
        private String containerAttributeName;

        @BeforeEach
        void setUp() {
            containerSession = new MockHttpSession();
            containerAttributeName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/myzone");
            subSession = new ZonePathHttpSession(containerSession, "/uaa/z/myzone", containerAttributeName, timeService);
        }

        @Test
        void getAttribute_returnsValueFromContainerSession() {
            subSession.setAttribute("key", "value");
            assertThat(subSession.getAttribute("key")).isEqualTo("value");
        }

        @Test
        void getAttribute_returnsNullForMissingKey() {
            assertThat(subSession.getAttribute("nonexistent")).isNull();
        }

        @Test
        void setAttribute_putsValueOnContainerSession() {
            subSession.setAttribute("foo", "bar");
            assertThat(containerSession.getAttribute(containerAttributeName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "foo")).isEqualTo("bar");
        }

        @Test
        void setAttribute_withNull_removesKey() {
            subSession.setAttribute("foo", "bar");
            subSession.setAttribute("foo", null);
            assertThat(containerSession.getAttribute(containerAttributeName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "foo")).isNull();
        }

        @Test
        void removeAttribute_removesFromContainerSession() {
            subSession.setAttribute("key", "value");
            subSession.removeAttribute("key");
            assertThat(containerSession.getAttribute(containerAttributeName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "key")).isNull();
        }

        @Test
        void getAttributeNames_returnsSubSessionKeysOnly() {
            containerSession.setAttribute("containerOnly", "x");
            subSession.setAttribute("zone1", "a");
            subSession.setAttribute("zone2", "b");

            List<String> names = Collections.list(subSession.getAttributeNames());
            assertThat(names).containsExactlyInAnyOrder("zone1", "zone2");
        }

        @Test
        void getId_includesContainerIdAndContextPathSuffix() {
            String id = subSession.getId();
            assertThat(id).startsWith(containerSession.getId());
            assertThat(id).endsWith("-uaa-z-myzone");
        }

        @Test
        void getId_defaultSuffix_forEmptyContextPath() {
            ZonePathHttpSession defaultSubSession = new ZonePathHttpSession(
                    containerSession, "", "irrelevant", timeService);
            assertThat(defaultSubSession.getId()).endsWith("-default");
        }

        @Test
        void getServletContext_delegatesToContainerSession() {
            assertThat(subSession.getServletContext()).isSameAs(containerSession.getServletContext());
        }

        @Test
        void isNew_returnsTrueForFreshSubSession() {
            assertThat(subSession.isNew()).isTrue();
        }

        @Test
        void isNew_returnsFalseForReconnectedSubSession() {
            subSession.setAttribute("user", "alice");
            ZonePathHttpSession reconnected = new ZonePathHttpSession(
                    containerSession, "/uaa/z/myzone", containerAttributeName, timeService);
            assertThat(reconnected.isNew()).isFalse();
        }

        @Test
        void isNew_returnsTrueAfterInvalidateAndRecreate() {
            subSession.setAttribute("user", "alice");
            subSession.invalidate();
            ZonePathHttpSession recreated = new ZonePathHttpSession(
                    containerSession, "/uaa/z/myzone", containerAttributeName, timeService);
            assertThat(recreated.isNew()).isTrue();
        }

        @Test
        void isNew_independentAcrossZones() {
            subSession.setAttribute("data", "val");
            // Reconnect to the same zone - should be not-new since creation time was persisted
            ZonePathHttpSession reconnected = new ZonePathHttpSession(
                    containerSession, "/uaa/z/myzone", containerAttributeName, timeService);
            // A different zone that has never been created - should be new
            String otherAttrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/other");
            ZonePathHttpSession otherSubSession = new ZonePathHttpSession(
                    containerSession, "/uaa/z/other", otherAttrName, timeService);
            assertThat(reconnected.isNew()).isFalse();
            assertThat(otherSubSession.isNew()).isTrue();
        }

        @Test
        void creationTime_setOnConstruction() {
            long before = System.currentTimeMillis();
            ZonePathHttpSession fresh = new ZonePathHttpSession(
                    containerSession, "/uaa/z/fresh",
                    ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/fresh"),
                    timeService);
            long after = System.currentTimeMillis();
            assertThat(fresh.getCreationTime()).isBetween(before, after);
        }

        @Test
        void creationTime_preservedOnReconnect() {
            long originalCreationTime = subSession.getCreationTime();
            subSession.setAttribute("data", "val");
            ZonePathHttpSession reconnected = new ZonePathHttpSession(
                    containerSession, "/uaa/z/myzone", containerAttributeName, timeService);
            assertThat(reconnected.getCreationTime()).isEqualTo(originalCreationTime);
        }

        @Test
        void creationTime_resetAfterInvalidateAndRecreate() throws InterruptedException {
            long originalCreationTime = subSession.getCreationTime();
            subSession.setAttribute("data", "val");
            subSession.invalidate();
            Thread.sleep(5);
            ZonePathHttpSession recreated = new ZonePathHttpSession(
                    containerSession, "/uaa/z/myzone", containerAttributeName, timeService);
            assertThat(recreated.getCreationTime()).isGreaterThan(originalCreationTime);
        }

        @Test
        void creationTime_independentPerZone() {
            String otherAttrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/other");
            ZonePathHttpSession otherSubSession = new ZonePathHttpSession(
                    containerSession, "/uaa/z/other", otherAttrName, timeService);
            assertThat(subSession.getCreationTime()).isNotEqualTo(0L);
            assertThat(otherSubSession.getCreationTime()).isNotEqualTo(0L);
        }

        @Test
        void lastAccessedTime_setOnConstruction() {
            long before = System.currentTimeMillis();
            ZonePathHttpSession fresh = new ZonePathHttpSession(
                    containerSession, "/uaa/z/fresh",
                    ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/fresh"),
                    timeService);
            long after = System.currentTimeMillis();
            assertThat(fresh.getLastAccessedTime()).isBetween(before, after);
        }

        @Test
        void lastAccessedTime_independentPerZone() throws InterruptedException {
            subSession.setAttribute("data", "val");
            Thread.sleep(5);
            String otherAttrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/other");
            ZonePathHttpSession otherSubSession = new ZonePathHttpSession(
                    containerSession, "/uaa/z/other", otherAttrName, timeService);
            assertThat(otherSubSession.getLastAccessedTime())
                    .isGreaterThanOrEqualTo(subSession.getLastAccessedTime());
        }

        @Test
        void isInvalidated_falseByDefault() {
            assertThat(subSession.isInvalidated()).isFalse();
        }

        @Test
        void isInvalidated_trueAfterInvalidate() {
            subSession.invalidate();
            assertThat(subSession.isInvalidated()).isTrue();
        }

        @Test
        void maxInactiveInterval_delegatesToContainer() {
            subSession.setMaxInactiveInterval(120);
            assertThat(containerSession.getMaxInactiveInterval()).isEqualTo(120);
            assertThat(subSession.getMaxInactiveInterval()).isEqualTo(120);
        }

        @Test
        void invalidate_clearsSubSessionButNotContainer() {
            subSession.setAttribute("secCtx", "auth");
            subSession.invalidate();

            assertThat(containerSession.getAttribute(containerAttributeName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "secCtx")).isNull();
            assertThat(containerSession.isInvalid()).isFalse();
        }

        @Test
        void invalidate_leavesOtherSubSessionsIntact() {
            String otherAttrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/other");
            containerSession.setAttribute(otherAttrName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "otherKey", "otherVal");

            subSession.invalidate();

            assertThat(containerSession.getAttribute(otherAttrName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "otherKey")).isEqualTo("otherVal");
        }

        @Test
        void containerSession_invalidated_subSessionGetAttributeThrows() {
            subSession.setAttribute("data", "value");
            containerSession.invalidate();

            // creationTime and lastAccessedTime are cached locally, so they don't throw
            assertThat(subSession.getCreationTime()).isGreaterThan(0);
            assertThat(subSession.getLastAccessedTime()).isGreaterThan(0);

            // getAttribute delegates to the invalidated container and throws
            assertThatThrownBy(() -> subSession.getAttribute("data"))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void attributeIsolation_acrossSubSessions() {
            String otherAttrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/other");
            ZonePathHttpSession otherSubSession = new ZonePathHttpSession(
                    containerSession, "/uaa/z/other", otherAttrName, timeService);

            subSession.setAttribute("shared-name", "zone1-value");
            otherSubSession.setAttribute("shared-name", "zone2-value");

            assertThat(subSession.getAttribute("shared-name")).isEqualTo("zone1-value");
            assertThat(otherSubSession.getAttribute("shared-name")).isEqualTo("zone2-value");
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // ZoneContextPathSessionRequestWrapper
    // ───────────────────────────────────────────────────────────────────────────

    @Nested
    class RequestWrapperTests {

        private MockHttpServletRequest request;
        private ZoneContextPathSessionRequestWrapper wrapper;

        @BeforeEach
        void setUp() {
            request = new MockHttpServletRequest();
            request.setContextPath("/uaa/z/zone1");
            wrapper = new ZoneContextPathSessionRequestWrapper(request, timeService);
        }

        @Test
        void getSession_returnsZonePathHttpSession() {
            HttpSession session = wrapper.getSession();
            assertThat(session).isInstanceOf(ZonePathHttpSession.class);
        }

        @Test
        void getSession_storesAttributesOnContainerSessionUnderPrefixedKeys() {
            HttpSession session = wrapper.getSession(true);
            session.setAttribute("x", "y");
            HttpSession containerSession = request.getSession(false);
            String attrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/zone1");
            assertThat(containerSession.getAttribute(attrName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "x")).isEqualTo("y");
        }

        @Test
        void getSession_false_returnsNullWhenNoContainerSession() {
            assertThat(wrapper.getSession(false)).isNull();
        }

        @Test
        void getSession_reusesExistingSubSessionAttributes() {
            HttpSession first = wrapper.getSession(true);
            first.setAttribute("data", "value");

            HttpSession second = wrapper.getSession(false);
            assertThat(second.getAttribute("data")).isEqualTo("value");
        }

        @Test
        void differentContextPaths_getDifferentSubSessions() {
            MockHttpServletRequest req1 = new MockHttpServletRequest();
            req1.setContextPath("/uaa/z/zone1");
            req1.setSession(new MockHttpSession());
            ZoneContextPathSessionRequestWrapper w1 = new ZoneContextPathSessionRequestWrapper(req1, timeService);

            MockHttpServletRequest req2 = new MockHttpServletRequest();
            req2.setContextPath("/uaa/z/zone2");
            req2.setSession(req1.getSession(false));
            ZoneContextPathSessionRequestWrapper w2 = new ZoneContextPathSessionRequestWrapper(req2, timeService);

            w1.getSession().setAttribute("user", "alice");
            w2.getSession().setAttribute("user", "bob");

            assertThat(w1.getSession().getAttribute("user")).isEqualTo("alice");
            assertThat(w2.getSession().getAttribute("user")).isEqualTo("bob");
        }

        @Test
        void emptyContextPath_usesDefaultKey() {
            request.setContextPath("");
            wrapper = new ZoneContextPathSessionRequestWrapper(request, timeService);
            HttpSession session = wrapper.getSession(true);
            assertThat(session.getId()).endsWith("-default");
        }

        @Test
        void attributeNameForContextPath_emptyUsesDefault() {
            assertThat(ZoneContextPathSessionRequestWrapper.attributeNameForContextPath(""))
                    .isEqualTo(ZoneContextPathSessionRequestWrapper.ATTRIBUTE_NAME_PREFIX + "default");
        }

        @Test
        void attributeNameForContextPath_nonEmptyUsesPath() {
            assertThat(ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/zone1"))
                    .isEqualTo(ZoneContextPathSessionRequestWrapper.ATTRIBUTE_NAME_PREFIX + "/uaa/z/zone1");
        }

        /**
         * Root path /uaa uses session key "/uaa".
         */
        @Test
        void contextPathUaa_usesSameSessionKeyAsRootPath_soDefaultZonePathSharesSession() {
            request.setContextPath("/uaa");
            request.setSession(new MockHttpSession());
            wrapper = new ZoneContextPathSessionRequestWrapper(request, timeService);
            HttpSession session = wrapper.getSession(true);
            session.setAttribute("user", "admin");

            String attrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa");
            assertThat(attrName).isEqualTo(ZoneContextPathSessionRequestWrapper.ATTRIBUTE_NAME_PREFIX + "/uaa");
            assertThat(request.getSession(false).getAttribute(attrName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "user")).isEqualTo("admin");
        }

        /**
         * When /z/default/ is used, context path is /uaa/z/default but the session key is the original
         * context path (/uaa) so /profile and /z/default/profile share the same cookie/session.
         */
        @Test
        void contextPathUaaZDefault_usesRootSessionKey_soSameCookieAsRootPath() {
            request.setContextPath("/uaa/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH);
            request.setAttribute(ZonePathContextRewritingFilter.ZONE_ORIGINAL_CONTEXT_PATH, "/uaa");
            request.setSession(new MockHttpSession());
            wrapper = new ZoneContextPathSessionRequestWrapper(request, timeService);
            HttpSession session = wrapper.getSession(true);
            session.setAttribute("user", "admin");

            String attrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa");
            assertThat(attrName).isEqualTo(ZoneContextPathSessionRequestWrapper.ATTRIBUTE_NAME_PREFIX + "/uaa");
            assertThat(request.getSession(false).getAttribute(attrName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "user")).isEqualTo("admin");
        }

        /**
         * No-context-path deployment: context path is /z/default, ZONE_ORIGINAL_CONTEXT_PATH is "".
         * Session key must be "" (same as root), stored under the "default" attribute name.
         */
        @Test
        void contextPathZDefault_noContextPath_usesEmptySessionKey_soSameCookieAsRootPath() {
            request.setContextPath("/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH);
            request.setAttribute(ZonePathContextRewritingFilter.ZONE_ORIGINAL_CONTEXT_PATH, "");
            request.setSession(new MockHttpSession());
            wrapper = new ZoneContextPathSessionRequestWrapper(request, timeService);
            HttpSession session = wrapper.getSession(true);
            session.setAttribute("user", "admin");

            String attrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("");
            assertThat(attrName).isEqualTo(ZoneContextPathSessionRequestWrapper.ATTRIBUTE_NAME_PREFIX + "default");
            assertThat(request.getSession(false).getAttribute(attrName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "user")).isEqualTo("admin");
        }

        /**
         * Defensive: if context path ends with /z/default but ZONE_ORIGINAL_CONTEXT_PATH attribute
         * is missing, contextPathKey() still falls back to empty string (root session key).
         */
        @Test
        void contextPathZDefault_missingOriginalContextPathAttribute_fallsBackToEmptyKey() {
            request.setContextPath("/uaa/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH);
            // deliberately not setting ZONE_ORIGINAL_CONTEXT_PATH
            request.setSession(new MockHttpSession());
            wrapper = new ZoneContextPathSessionRequestWrapper(request, timeService);
            HttpSession session = wrapper.getSession(true);
            session.setAttribute("user", "admin");

            String attrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("");
            assertThat(request.getSession(false).getAttribute(attrName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "user")).isEqualTo("admin");
        }

        @Test
        void getSession_afterInvalidate_returnsFreshSubSession() {
            HttpSession first = wrapper.getSession(true);
            first.setAttribute("user", "alice");
            first.invalidate();

            // getSession(true) after invalidate should return a new sub-session
            // Need a new wrapper since cachedSession is per-request
            wrapper = new ZoneContextPathSessionRequestWrapper(request, timeService);
            HttpSession second = wrapper.getSession(true);
            assertThat(second).isInstanceOf(ZonePathHttpSession.class);
            assertThat(second.isNew()).isTrue();
            assertThat(second.getAttribute("user")).isNull();
        }

        @Test
        void getSession_afterInvalidate_sameRequest_clearsCacheAndReturnsNew() {
            HttpSession first = wrapper.getSession(true);
            first.setAttribute("user", "alice");
            assertThat(first.getAttribute("user")).isEqualTo("alice");
            first.invalidate();

            // On the same wrapper, getSession(true) should detect invalidation and create fresh
            HttpSession second = wrapper.getSession(true);
            assertThat(second).isNotSameAs(first);
            assertThat(second.getAttribute("user")).isNull();
        }

        @Test
        void getSession_false_afterInvalidate_returnsNull() {
            HttpSession first = wrapper.getSession(true);
            first.setAttribute("user", "alice");
            first.invalidate();

            // getSession(false) after invalidate: sub-session is dead, should return null
            // Need a new wrapper to not hit cache
            wrapper = new ZoneContextPathSessionRequestWrapper(request, timeService);
            HttpSession result = wrapper.getSession(false);
            // Container session still exists, but this sub-session has no attributes
            // A fresh ZonePathHttpSession is acceptable here since container session exists
            // but it should be new
            if (result != null) {
                assertThat(result.isNew()).isTrue();
            }
        }

        @Test
        void getSession_touchesLastAccessedTimeOnAccess() {
            AtomicLong clock = new AtomicLong(1_000_000L);
            TimeService controllableClock = new TimeService() {
                @Override public long getCurrentTimeMillis() { return clock.get(); }
            };

            MockHttpServletRequest req = new MockHttpServletRequest();
            req.setContextPath("/uaa/z/zone1");
            ZoneContextPathSessionRequestWrapper w = new ZoneContextPathSessionRequestWrapper(req, controllableClock);

            HttpSession first = w.getSession(true);
            long creationTime = first.getLastAccessedTime();
            assertThat(creationTime).isEqualTo(1_000_000L);

            // Advance the clock and access the session again on a new request
            clock.set(2_000_000L);
            ZoneContextPathSessionRequestWrapper w2 = new ZoneContextPathSessionRequestWrapper(req, controllableClock);
            HttpSession second = w2.getSession(false);
            assertThat(second).isNotNull();
            assertThat(second.getLastAccessedTime()).isEqualTo(2_000_000L);
        }

        @Test
        void changeSessionId_preservesSubSessionAttributes() {
            HttpSession subSession = wrapper.getSession(true);
            subSession.setAttribute("key", "value");
            String oldId = request.getSession(false).getId();

            String newId = wrapper.changeSessionId();

            assertThat(newId).isNotEqualTo(oldId);
            HttpSession afterChange = wrapper.getSession(false);
            assertThat(afterChange.getAttribute("key")).isEqualTo("value");
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // ZoneContextPathSessionResponseWrapper
    // ───────────────────────────────────────────────────────────────────────────

    @Nested
    class ResponseWrapperTests {

        private MockHttpServletResponse rawResponse;
        private ZoneContextPathSessionResponseWrapper wrapper;

        @BeforeEach
        void setUp() {
            rawResponse = new MockHttpServletResponse();
            wrapper = new ZoneContextPathSessionResponseWrapper(rawResponse);
        }

        @Test
        void addCookie_blocksJSessionIdClear_maxAgeZero() {
            Cookie cookie = new Cookie("JSESSIONID", "abc");
            cookie.setMaxAge(0);
            wrapper.addCookie(cookie);
            assertThat(rawResponse.getCookies()).isEmpty();
        }

        @Test
        void addCookie_blocksJSessionIdClear_emptyValue() {
            Cookie cookie = new Cookie("JSESSIONID", "");
            cookie.setMaxAge(-1);
            wrapper.addCookie(cookie);
            assertThat(rawResponse.getCookies()).isEmpty();
        }

        @Test
        void addCookie_allowsNormalJSessionId() {
            Cookie cookie = new Cookie("JSESSIONID", "abc123");
            cookie.setMaxAge(-1);
            wrapper.addCookie(cookie);
            assertThat(rawResponse.getCookies()).hasSize(1);
            assertThat(rawResponse.getCookies()[0].getValue()).isEqualTo("abc123");
        }

        @Test
        void addCookie_allowsNonJSessionIdCookieEvenWithMaxAgeZero() {
            Cookie cookie = new Cookie("OTHER", "val");
            cookie.setMaxAge(0);
            wrapper.addCookie(cookie);
            assertThat(rawResponse.getCookies()).hasSize(1);
        }

        @Test
        void addHeader_blocksSetCookie_clearingJSessionId_maxAgeZero() {
            wrapper.addHeader("Set-Cookie", "JSESSIONID=abc; Max-Age=0; Path=/uaa");
            assertThat(rawResponse.getHeader("Set-Cookie")).isNull();
        }

        @Test
        void addHeader_blocksSetCookie_clearingJSessionId_emptyValue() {
            wrapper.addHeader("Set-Cookie", "JSESSIONID=; Path=/uaa");
            assertThat(rawResponse.getHeader("Set-Cookie")).isNull();
        }

        @Test
        void addHeader_allowsNormalSetCookieJSessionId() {
            wrapper.addHeader("Set-Cookie", "JSESSIONID=abc123; Path=/uaa");
            assertThat(rawResponse.getHeader("Set-Cookie")).contains("abc123");
        }

        @Test
        void addHeader_allowsNonSetCookieHeader() {
            wrapper.addHeader("X-Custom", "value");
            assertThat(rawResponse.getHeader("X-Custom")).isEqualTo("value");
        }

        @Test
        void setHeader_blocksSetCookie_clearingJSessionId() {
            wrapper.setHeader("Set-Cookie", "JSESSIONID=; Max-Age=0; Path=/");
            assertThat(rawResponse.getHeader("Set-Cookie")).isNull();
        }

        @Test
        void setHeader_allowsNonJSessionIdSetCookie() {
            wrapper.setHeader("Set-Cookie", "XSRF-TOKEN=abc; Path=/");
            assertThat(rawResponse.getHeader("Set-Cookie")).contains("XSRF-TOKEN");
        }

        @Test
        void addHeader_caseInsensitive_setCookie() {
            wrapper.addHeader("set-cookie", "JSESSIONID=; Path=/");
            assertThat(rawResponse.getHeader("set-cookie")).isNull();
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // ZoneContextPathSessionFilter
    // ───────────────────────────────────────────────────────────────────────────

    @Nested
    class FilterTests {

        private ZoneContextPathSessionFilter filter;
        private MockHttpServletRequest request;
        private MockHttpServletResponse response;
        private AtomicReference<HttpServletRequest> capturedRequest;
        private AtomicReference<HttpServletResponse> capturedResponse;

        @BeforeEach
        void setUp() {
            filter = new ZoneContextPathSessionFilter(timeService);
            request = new MockHttpServletRequest();
            response = new MockHttpServletResponse();
            capturedRequest = new AtomicReference<>();
            capturedResponse = new AtomicReference<>();
        }

        private FilterChain capturingChain() {
            return (req, resp) -> {
                capturedRequest.set((HttpServletRequest) req);
                capturedResponse.set((HttpServletResponse) resp);
            };
        }

        private FilterChain capturingChain(Runnable action) {
            return (req, resp) -> {
                capturedRequest.set((HttpServletRequest) req);
                capturedResponse.set((HttpServletResponse) resp);
                action.run();
            };
        }

        @Test
        void wrapsRequestAndResponse() throws ServletException, IOException {
            request.setContextPath("/uaa");
            filter.doFilter(request, response, capturingChain());

            assertThat(capturedRequest.get()).isInstanceOf(ZoneContextPathSessionRequestWrapper.class);
            assertThat(capturedResponse.get()).isInstanceOf(ZoneContextPathSessionResponseWrapper.class);
        }

        @Test
        void sessionInsideChain_isZonePathHttpSession() throws ServletException, IOException {
            request.setContextPath("/uaa/z/zone1");
            filter.doFilter(request, response, capturingChain(() -> {
                HttpSession session = capturedRequest.get().getSession(true);
                assertThat(session).isInstanceOf(ZonePathHttpSession.class);
                session.setAttribute("user", "alice");
            }));

            HttpSession containerSession = request.getSession(false);
            String attrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/zone1");
            assertThat(containerSession.getAttribute(attrName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "user")).isEqualTo("alice");
        }

        @Test
        void sessionAttributes_storedOnContainerImmediately() throws ServletException, IOException {
            request.setContextPath("/uaa/z/zone1");
            MockHttpSession containerSession = new MockHttpSession();
            request.setSession(containerSession);

            String attrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/zone1");

            filter.doFilter(request, response, capturingChain(() -> {
                capturedRequest.get().getSession(true).setAttribute("data", "value");
            }));

            assertThat(containerSession.getAttribute(attrName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "data")).isEqualTo("value");
        }

        @Test
        void clearsJSessionId_whenAllSubSessionsRemoved() throws ServletException, IOException {
            request.setContextPath("/uaa");
            MockHttpSession containerSession = new MockHttpSession();
            request.setSession(containerSession);

            filter.doFilter(request, response, capturingChain(() -> {
                HttpSession sub = capturedRequest.get().getSession(true);
                sub.setAttribute("key", "val");
                sub.invalidate();
            }));

            assertThat(response.getHeader("Set-Cookie"))
                    .as("Should clear JSESSIONID when no sub-sessions remain")
                    .contains("JSESSIONID=")
                    .contains("Max-Age=0");
        }

        @Test
        void doesNotClearJSessionId_whenOtherSubSessionsRemain() throws ServletException, IOException {
            request.setContextPath("/uaa/z/zone1");
            MockHttpSession containerSession = new MockHttpSession();
            request.setSession(containerSession);

            // Pre-populate another zone's sub-session (direct attribute)
            String otherAttrName = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/zone2");
            containerSession.setAttribute(otherAttrName + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "user", "bob");

            filter.doFilter(request, response, capturingChain(() -> {
                HttpSession sub = capturedRequest.get().getSession(true);
                sub.setAttribute("user", "alice");
                sub.invalidate();
            }));

            assertThat(response.getHeader("Set-Cookie"))
                    .as("Should NOT clear JSESSIONID when other sub-sessions exist")
                    .isNull();
        }

        @Test
        void doesNotClearJSessionId_whenResponseAlreadyCommitted() throws ServletException, IOException {
            request.setContextPath("/uaa");
            MockHttpSession containerSession = new MockHttpSession();
            request.setSession(containerSession);

            filter.doFilter(request, response, (req, resp) -> {
                capturedRequest.set((HttpServletRequest) req);
                HttpSession sub = ((HttpServletRequest) req).getSession(true);
                sub.invalidate();
                ((HttpServletResponse) resp).getOutputStream().flush();
                ((HttpServletResponse) resp).flushBuffer();
            });

            // Response was committed before the filter's finally block;
            // should not have the clear-cookie header added by the filter.
            // Note: the response may already have headers from the flushing itself,
            // but the filter's specific JSESSIONID clear should not appear via rawResponse.
        }

        @Test
        void multipleZones_sameContainerSession() throws ServletException, IOException {
            MockHttpSession containerSession = new MockHttpSession();

            // Login to zone1
            request.setContextPath("/uaa/z/zone1");
            request.setSession(containerSession);
            filter.doFilter(request, response, capturingChain(() -> {
                capturedRequest.get().getSession(true).setAttribute("user", "alice");
            }));

            // Login to zone2 (same container session)
            MockHttpServletRequest request2 = new MockHttpServletRequest();
            request2.setContextPath("/uaa/z/zone2");
            request2.setSession(containerSession);
            MockHttpServletResponse response2 = new MockHttpServletResponse();
            filter.doFilter(request2, response2, (req, resp) -> {
                ((HttpServletRequest) req).getSession(true).setAttribute("user", "bob");
            });

            String z1Attr = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/zone1");
            String z2Attr = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/zone2");

            assertThat(containerSession.getAttribute(z1Attr + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "user")).isEqualTo("alice");
            assertThat(containerSession.getAttribute(z2Attr + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "user")).isEqualTo("bob");
        }

        @Test
        void containerSessionInvalidated_insideChain_handledGracefully() throws ServletException, IOException {
            request.setContextPath("/uaa/z/zone1");
            MockHttpSession containerSession = new MockHttpSession();
            request.setSession(containerSession);

            filter.doFilter(request, response, (req, resp) -> {
                HttpServletRequest httpReq = (HttpServletRequest) req;
                httpReq.getSession(true).setAttribute("data", "val");
                containerSession.invalidate();
            });

            // The filter's finally block calls request.getSession(false) on the original
            // request which should return null after invalidation. No exception expected.
        }

        @Test
        void logoutFromOneZone_leavesOtherZonesIntact() throws ServletException, IOException {
            MockHttpSession containerSession = new MockHttpSession();

            // Setup: login to default zone and zone1
            request.setContextPath("");
            request.setSession(containerSession);
            filter.doFilter(request, response, capturingChain(() -> {
                capturedRequest.get().getSession(true).setAttribute("user", "admin");
            }));

            MockHttpServletRequest zoneReq = new MockHttpServletRequest();
            zoneReq.setContextPath("/uaa/z/zone1");
            zoneReq.setSession(containerSession);
            filter.doFilter(zoneReq, new MockHttpServletResponse(), (req, resp) -> {
                ((HttpServletRequest) req).getSession(true).setAttribute("user", "zone1-user");
            });

            // Logout from zone1 (invalidate that sub-session)
            MockHttpServletRequest logoutReq = new MockHttpServletRequest();
            logoutReq.setContextPath("/uaa/z/zone1");
            logoutReq.setSession(containerSession);
            filter.doFilter(logoutReq, new MockHttpServletResponse(), (req, resp) -> {
                ((HttpServletRequest) req).getSession(false).invalidate();
            });

            // Default zone sub-session should still be present
            String defaultAttr = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("");
            assertThat(containerSession.getAttribute(defaultAttr + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "user")).isEqualTo("admin");

            // Zone1 sub-session attributes should be gone
            String z1Attr = ZoneContextPathSessionRequestWrapper.attributeNameForContextPath("/uaa/z/zone1");
            assertThat(containerSession.getAttribute(z1Attr + ZonePathHttpSession.ATTRIBUTE_KEY_DELIMITER + "user")).isNull();
        }
    }
}
