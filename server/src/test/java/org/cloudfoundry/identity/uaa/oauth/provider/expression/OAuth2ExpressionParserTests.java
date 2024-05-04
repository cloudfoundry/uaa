package org.cloudfoundry.identity.uaa.oauth.provider.expression;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParserContext;

import static org.mockito.Mockito.verify;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2ExpressionParserTests {
	@Mock
	private ExpressionParser delegate;
	@Mock
	private ParserContext parserContext;

	private final String expressionString = "ORIGIONAL";

	private final String wrappedExpression = "#oauth2.throwOnError(" + expressionString + ")";

	private OAuth2ExpressionParser parser;
	
	@Before
	public void setUp() {
		parser = new OAuth2ExpressionParser(delegate);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNull() {
		new OAuth2ExpressionParser(null);
	}
	
	@Test
	public void parseExpression() {
		parser.parseExpression(expressionString);
		verify(delegate).parseExpression(wrappedExpression);
	}
	
	@Test
	public void parseExpressionWithContext() {
		parser.parseExpression(expressionString, parserContext);
		verify(delegate).parseExpression(wrappedExpression, parserContext);
	}
}
