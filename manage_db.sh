rm ./data/burp-probe.db
flask init
sqlite3 ./data/burp-probe.db < migrate.sql
flask migrate
