package org.cloudfoundry.identity.uaa.oauth.provider.expression;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.expression.ParserContext;
import org.springframework.util.Assert;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class OAuth2ExpressionParser implements ExpressionParser {

    private final ExpressionParser delegate;

    public OAuth2ExpressionParser(ExpressionParser delegate) {
        Assert.notNull(delegate, "delegate cannot be null");
        this.delegate = delegate;
    }

    public Expression parseExpression(String expressionString) throws ParseException {
        return delegate.parseExpression(wrapExpression(expressionString));
    }

    public Expression parseExpression(String expressionString, ParserContext context) throws ParseException {
        return delegate.parseExpression(wrapExpression(expressionString), context);
    }

    private String wrapExpression(String expressionString) {
        return "#oauth2.throwOnError(" + expressionString + ")";
    }
}