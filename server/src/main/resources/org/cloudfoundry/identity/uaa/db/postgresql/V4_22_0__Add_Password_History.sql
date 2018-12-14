CREATE TABLE password_history (
   id SERIAL PRIMARY KEY,
   user_id CHAR(36) NOT NULL,
   identity_zone_id CHAR(36) NOT NULL,
   password VARCHAR(255) NOT NULL,
   changed TIMESTAMP NOT NULL
) ;
