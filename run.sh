source ~/.zshrc
venv_activate burp-probe
if [ ! -f ./data/burp-probe.db ]; then
    flask init
fi
flask run $@
deactivate
