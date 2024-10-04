package org.cloudfoundry.identity.uaa.oauth.provider.error;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Moved class AbstractOAuth2SecurityExceptionHandler implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 */
public abstract class AbstractOAuth2SecurityExceptionHandler {

	/** Logger available to subclasses */
	protected final Log logger = LogFactory.getLog(getClass());

	private WebResponseExceptionTranslator<?> exceptionTranslator = new DefaultWebResponseExceptionTranslator();

	private OAuth2ExceptionRenderer exceptionRenderer = new DefaultOAuth2ExceptionRenderer();

	// This is from Spring MVC.
	private HandlerExceptionResolver handlerExceptionResolver = new DefaultHandlerExceptionResolver();

	public void setExceptionTranslator(WebResponseExceptionTranslator<?> exceptionTranslator) {
		this.exceptionTranslator = exceptionTranslator;
	}

	public void setExceptionRenderer(OAuth2ExceptionRenderer exceptionRenderer) {
		this.exceptionRenderer = exceptionRenderer;
	}

	protected final void doHandle(HttpServletRequest request, HttpServletResponse response, Exception authException)
			throws IOException, ServletException {
		try {
			ResponseEntity<?> result = exceptionTranslator.translate(authException);
			result = enhanceResponse(result, authException);
			exceptionRenderer.handleHttpEntityResponse(result, new ServletWebRequest(request, response));
			response.flushBuffer();
		}
		catch (ServletException e) {
			// Re-use some of the default Spring dispatcher behaviour - the exception came from the filter chain and
			// not from an MVC handler so it won't be caught by the dispatcher (even if there is one)
			if (handlerExceptionResolver.resolveException(request, response, this, e) == null) {
				throw e;
			}
		}
		catch (RuntimeException | IOException e) {
			throw e;
		}
		catch (Exception e) {
			// Wrap other Exceptions. These are not expected to happen
			throw new RuntimeException(e);
		}
	}

	/**
	 * Allow subclasses to manipulate the response before it is rendered.
	 * 
	 * Note : Only the {@link ResponseEntity} should be enhanced. If the
         * response body is to be customized, it should be done at the
         * {@link WebResponseExceptionTranslator} level.
	 * 
	 * @param result the response that was generated by the
	 * {@link #setExceptionTranslator(WebResponseExceptionTranslator) exception translator}.
	 * @param authException the authentication exception that is being handled
	 */
	protected ResponseEntity<?> enhanceResponse(ResponseEntity<?> result,
			Exception authException) {
		return result;
	}

}
