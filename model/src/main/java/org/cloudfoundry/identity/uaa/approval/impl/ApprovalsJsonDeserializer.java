package org.cloudfoundry.identity.uaa.approval.impl;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import java.io.IOException;
import java.util.Date;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;

public class ApprovalsJsonDeserializer extends JsonDeserializer<Approval> {

  @Override
  public Approval deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
    Approval approval = new Approval();
    while (jp.nextToken() != JsonToken.END_OBJECT) {
      if (jp.getCurrentToken() == JsonToken.FIELD_NAME) {
        String fieldName = jp.getCurrentName();
        jp.nextToken();
        if ("userId".equalsIgnoreCase(fieldName)) {
          approval.setUserId(jp.readValueAs(String.class));
        } else if ("clientId".equalsIgnoreCase(fieldName)) {
          approval.setClientId(jp.readValueAs(String.class));
        } else if ("scope".equalsIgnoreCase(fieldName)) {
          approval.setScope(jp.readValueAs(String.class));
        } else if ("status".equalsIgnoreCase(fieldName)) {
          approval.setStatus(jp.readValueAs(ApprovalStatus.class));
        } else if ("expiresAt".equalsIgnoreCase(fieldName)) {
          approval.setExpiresAt(jp.readValueAs(Date.class));
        } else if ("lastUpdatedAt".equalsIgnoreCase(fieldName)) {
          approval.setLastUpdatedAt(jp.readValueAs(Date.class));
        }
      }
    }
    return approval;
  }
}
