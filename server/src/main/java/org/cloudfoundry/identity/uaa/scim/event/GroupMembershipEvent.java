package org.cloudfoundry.identity.uaa.scim.event;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.io.Serial;
import java.util.Set;

public final class GroupMembershipEvent extends AbstractUaaEvent {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String groupId;
    private final AuditEventType type;
    private final MembershipInfo info;

    GroupMembershipEvent(ScimGroup group, ScimGroupMember member, String memberName,
            AuditEventType type, String zoneId) {
        super(getContextAuthentication(), zoneId);
        this.groupId = group.getId();
        this.type = type;
        this.info = new MembershipInfo(group.getDisplayName(), member.getMemberId(), memberName,
                member.getType() == null ? ScimGroupMember.Type.USER : member.getType());
    }

    boolean describesChange(Set<String> before, Set<String> after) {
        String memberId = info.memberId();
        return type == AuditEventType.GroupMembershipAddedEvent
                ? !before.contains(memberId) && after.contains(memberId)
                : before.contains(memberId) && !after.contains(memberId);
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(groupId, type, getOrigin(getAuthentication()), JsonUtils.writeValueAsString(info));
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record MembershipInfo(
            @JsonProperty("group_name") String groupName,
            @JsonProperty("member_id") String memberId,
            @JsonProperty("member_name") String memberName,
            @JsonProperty("member_type") ScimGroupMember.Type memberType) {
    }
}
