package org.cloudfoundry.identity.uaa.cache.infinispan;

import java.io.IOException;

import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType;
import org.infinispan.protostream.MessageMarshaller;

public class RevocableTokenSerializer implements MessageMarshaller<RevocableToken> {
	

	@Override
	public void writeTo(ProtoStreamWriter out, RevocableToken token) throws IOException {
		out.writeInt("tokenType",token.getResponseType().ordinal());
		out.writeString("clientId",token.getClientId());
		out.writeString("userId",token.getUserId());
		out.writeString("scope",token.getScope());
		out.writeString("format",token.getFormat());
		out.writeString("zoneId",token.getZoneId());
		out.writeString("value",token.getValue());
	    out.writeLong("expiresAt",token.getExpiresAt());
	    out.writeLong("issuedAt",token.getIssuedAt());
	    out.writeString("tokenId",token.getTokenId());
	}

	@Override
	public RevocableToken readFrom(ProtoStreamReader in) throws IOException {
		RevocableToken token = new RevocableToken();
		token.setResponseType(TokenType.values()[ in.readInt("tokenType") ]);		
		token.setClientId(in.readString("clientId"));
		token.setUserId(in.readString("userId"));
		token.setScope(in.readString("scope"));
		token.setFormat(in.readString("format"));
		token.setZoneId(in.readString("zoneId"));
		token.setValue(in.readString("value"));
		token.setExpiresAt(in.readLong("expiresAt"));
		token.setIssuedAt(in.readLong("issuedAt"));
		token.setTokenId(in.readString("tokenId"));
		return token;
	}

	

	@Override
	public Class<? extends RevocableToken> getJavaClass() {
		return RevocableToken.class;
	}

	@Override
	public String getTypeName() {
		return "uaa.RevocableToken";
	}

}