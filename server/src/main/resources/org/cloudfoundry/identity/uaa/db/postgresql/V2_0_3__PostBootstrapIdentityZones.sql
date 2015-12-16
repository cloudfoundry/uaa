--
-- Cloud Foundry
-- Copyright (c) [2015] Pivotal Software, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--
ALTER TABLE oauth_client_details ALTER COLUMN identity_zone_id SET NOT NULL;
ALTER TABLE users ALTER COLUMN identity_zone_id SET NOT NULL;

DROP INDEX IF EXISTS users_unique_key;
CREATE UNIQUE INDEX username_in_idp ON users (identity_provider_id,LOWER(username));

ALTER TABLE oauth_client_details DROP CONSTRAINT oauth_client_details_pkey;
ALTER TABLE oauth_client_details ADD PRIMARY KEY (client_id,identity_zone_id);
