CREATE TABLE password_history (
   id INTEGER IDENTITY (1,1) PRIMARY KEY,
   user_id CHAR(36) NOT NULL,
   identity_zone_id CHAR(36) NOT NULL,
   password NVARCHAR(255) NOT NULL,
   changed DATETIME NOT NULL
) ;
