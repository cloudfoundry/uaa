sp_configure 'contained database authentication', 1
go
RECONFIGURE
go
CREATE DATABASE uaa CONTAINMENT = PARTIAL;
go
USE uaa;
go
CREATE USER root WITH PASSWORD = 'changemeCHANGEME1234!';
go
EXEC sp_addrolemember N'db_owner', N'root';
go