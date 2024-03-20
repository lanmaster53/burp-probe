ATTACH 'old.db' AS ORIG;
INSERT INTO table_name (column_name) SELECT column_name from ORIG.table_name;
