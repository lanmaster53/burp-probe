from flask import Blueprint, session, request, redirect, url_for, flash, render_template
from burp_probe.decorators import login_required
from burp_probe.models import User
from burp_probe.schemas import login_form_schema

blp = Blueprint('auth', __name__)

@blp.route('/login')
def login():
    if session.get('user_id'):
        return redirect(url_for('core.home'))
    return render_template('pages/login.html')

@blp.route('/login', methods=['POST'])
def login_submit():
    errors = login_form_schema.validate(request.form)
    if errors:
        return render_template(
            'pages/login.html',
            errors=errors,
        ), 400
    user = User.query.filter_by(email=request.form.get('email')).first()
    if user and user.check_password(request.form.get('password')):
        session['user_id'] = user.id
        return redirect(url_for('core.home'))
    flash('Invalid email or password.', category='error')
    return render_template('pages/login.html')

@blp.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.clear()
    return redirect(url_for('core.index'))
