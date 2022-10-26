UPDATE group_membership SET identity_zone_id = (SELECT identity_zone_id FROM users where users.id = group_membership.member_id) WHERE member_type='USER';
UPDATE group_membership SET identity_zone_id = (SELECT 'uaa' FROM `groups` where `groups`.id = group_membership.member_id) WHERE member_type='GROUP';
