source ~/.zshrc
venv_activate enterprize
gunicorn "enterprize:create_app('Development')" --worker-class gevent --bind 127.0.0.1:5000 --reload
#flask run $@
deactivate
