--
-- Copyright (c) [2016] Microsoft, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--
UPDATE group_membership SET identity_zone_id = (SELECT identity_zone_id FROM users where users.id = group_membership.member_id) WHERE member_type='USER';
UPDATE group_membership SET identity_zone_id = (SELECT 'uaa' FROM groups where groups.id = group_membership.member_id) WHERE member_type='GROUP';
