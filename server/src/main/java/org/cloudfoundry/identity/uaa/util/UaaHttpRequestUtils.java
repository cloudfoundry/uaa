package org.cloudfoundry.identity.uaa.util;

import static java.util.Arrays.stream;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

public abstract class UaaHttpRequestUtils {

  private static Logger logger = LoggerFactory.getLogger(UaaHttpRequestUtils.class);

  public static ClientHttpRequestFactory createRequestFactory(
      boolean skipSslValidation, int timeout) {
    return createRequestFactory(getClientBuilder(skipSslValidation), timeout);
  }

  protected static ClientHttpRequestFactory createRequestFactory(
      HttpClientBuilder builder, int timeoutInMs) {
    HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory =
        new HttpComponentsClientHttpRequestFactory(builder.build());

    httpComponentsClientHttpRequestFactory.setReadTimeout(timeoutInMs);
    httpComponentsClientHttpRequestFactory.setConnectionRequestTimeout(timeoutInMs);
    httpComponentsClientHttpRequestFactory.setConnectTimeout(timeoutInMs);
    return httpComponentsClientHttpRequestFactory;
  }

  protected static HttpClientBuilder getClientBuilder(boolean skipSslValidation) {
    HttpClientBuilder builder =
        HttpClients.custom()
            .useSystemProperties()
            .setRedirectStrategy(new DefaultRedirectStrategy());
    if (skipSslValidation) {
      builder.setSslcontext(getNonValidatingSslContext());
      builder.setSSLHostnameVerifier(new NoopHostnameVerifier());
    }
    builder.setConnectionReuseStrategy(NoConnectionReuseStrategy.INSTANCE);
    return builder;
  }

  private static SSLContext getNonValidatingSslContext() {
    try {
      return new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
    } catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public static String paramsToQueryString(Map<String, String[]> parameterMap) {
    return parameterMap.entrySet().stream()
        .flatMap(
            param ->
                stream(param.getValue())
                    .map(value -> param.getKey() + "=" + encodeParameter(value)))
        .collect(Collectors.joining("&"));
  }

  private static String encodeParameter(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  public static boolean isAcceptedInvitationAuthentication() {
    try {
      RequestAttributes attr = RequestContextHolder.currentRequestAttributes();
      if (attr != null) {
        Boolean result =
            (Boolean) attr.getAttribute("IS_INVITE_ACCEPTANCE", RequestAttributes.SCOPE_SESSION);
        if (result != null) {
          return result;
        }
      }
    } catch (IllegalStateException x) {
      // nothing bound on thread.
      logger.debug("Unable to retrieve request attributes looking for invitation.");
    }
    return false;
  }
}
