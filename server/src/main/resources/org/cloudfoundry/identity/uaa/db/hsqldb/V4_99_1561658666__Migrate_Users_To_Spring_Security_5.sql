UPDATE users
SET password = CONCAT('{bcrypt}', password)