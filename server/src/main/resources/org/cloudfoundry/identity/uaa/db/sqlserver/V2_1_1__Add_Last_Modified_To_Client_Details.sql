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
ALTER TABLE oauth_client_details ADD lastmodified DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL;

EXEC sp_rename 'identity_provider.lastModified', 'lastmodified', 'COLUMN';

EXEC sp_rename 'identity_zone.lastModified', 'lastmodified', 'COLUMN';