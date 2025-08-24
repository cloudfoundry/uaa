package org.cloudfoundry.identity.uaa.oauth.provider.expression;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParserContext;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.verify;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
@ExtendWith(MockitoExtension.class)
class OAuth2ExpressionParserTests {
    @Mock
    private ExpressionParser delegate;
    @Mock
    private ParserContext parserContext;

    private final String expressionString = "ORIGIONAL";

    private final String wrappedExpression = "#oauth2.throwOnError(" + expressionString + ")";

    private OAuth2ExpressionParser parser;

    @BeforeEach
    void setUp() {
        parser = new OAuth2ExpressionParser(delegate);
    }

    @Test
    void constructorNull() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> {
            new OAuth2ExpressionParser(null);
        });
    }

    @Test
    void parseExpression() {
        parser.parseExpression(expressionString);
        verify(delegate).parseExpression(wrappedExpression);
    }

    @Test
    void parseExpressionWithContext() {
        parser.parseExpression(expressionString, parserContext);
        verify(delegate).parseExpression(wrappedExpression, parserContext);
    }
}
