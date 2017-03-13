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

-- HSQLDB does not support indices with function - but we create this one to keep it in synch with the other schemas
CREATE INDEX sec_audit_principal_idx ON sec_audit(principal_id);
CREATE INDEX sec_audit_created_idx ON sec_audit(created);