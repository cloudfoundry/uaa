--
-- Cloud Foundry 2012.02.03 Beta
-- Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--

CREATE TABLE USERS (
   id SERIAL primary key,
   created_at TIMESTAMP default current_timestamp not null,
   updated_at TIMESTAMP default current_timestamp not null,
   active boolean default true not null,
   crypted_password VARCHAR(255) not null,
   email VARCHAR(255) not null,
   constraint unique_uk_1 unique(email)
) ;