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
ALTER TABLE oauth_client_details ADD show_on_home_page BIT DEFAULT 1 NOT NULL;
ALTER TABLE oauth_client_details ADD app_launch_url VARCHAR(1024);
ALTER TABLE oauth_client_details ADD app_icon VARBINARY(max);
