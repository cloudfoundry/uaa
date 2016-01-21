ALTER TABLE oauth_client_details ADD COLUMN show_on_home_page BOOLEAN DEFAULT TRUE NOT NULL;
ALTER TABLE oauth_client_details ADD COLUMN app_launch_url VARCHAR(1024);
ALTER TABLE oauth_client_details ADD COLUMN app_icon BYTEA;
