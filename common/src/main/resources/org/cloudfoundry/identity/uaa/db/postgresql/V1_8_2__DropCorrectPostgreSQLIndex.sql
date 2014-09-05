-- remove a unique key that should not exist
-- https://www.pivotaltracker.com/story/show/77877632
DROP INDEX IF EXISTS unique_uk_1_1;
