source ~/.zshrc
venv_activate burp-probe
flask run $@
deactivate
