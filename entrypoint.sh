if [ ! -f ./data/burp-probe.db ]; then
    flask init
fi
#gunicorn --bind 0.0.0.0:80 "burp_probe:create_app('Development')" --error-logfile - --log-level DEBUG --reload
gunicorn --bind 0.0.0.0:80 "burp_probe:create_app('Production')"
