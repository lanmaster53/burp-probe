rm ./data/enterprize.db
flask init
sqlite3 ./data/enterprize.db < migrate.sql
flask migrate
