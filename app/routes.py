from io import BytesIO
from flask import render_template, flash, redirect, url_for, make_response, send_file, Response
from app import app, db
from app.forms import LoginForm, RegistrationForm, CSRForm, CertForm, EditProfileForm, ResetPasswordForm
from flask_login import current_user, login_user
from app.models import User, Certificate
from flask_login import logout_user
from flask_login import login_required
from flask import request
from werkzeug.urls import url_parse
from OpenSSL import crypto
from OpenSSL import SSL
from datetime import datetime


@app.route('/')
@app.route('/index')
@login_required
def index():
    user = {'username': 'test'}
    certificate = [
        {
            'author': {'username': 'John'},
            'body': 'Beautiful day in Portland!'
        },
        {
            'author': {'username': 'Susan'},
            'body': 'The Avengers movie was so cool!'
        }
    ]
    return render_template("index.html", title='Home Page', certificate=certificate)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/generate_csr", methods=["GET", "POST"])
@login_required
def generate_csr():
    form = CSRForm()
    if form.validate_on_submit():
        # retrieve form data and generate CSR
        data = request.form
        country = data['country']
        state = data['state']
        locality = data['locality']
        organization = data['organization']
        organizational_unit = data['organizational_unit']
        common_name = data['common_name']
        subject_alternative_name = data['subject_alternative_name']

        #Create Keypair
        keypair = crypto.PKey()
        keypair.generate_key(crypto.TYPE_RSA, 2048)

        # Create a certificate request
        req = crypto.X509Req()
        req.get_subject().CN = common_name
        req.get_subject().C = country
        req.get_subject().ST = state
        req.get_subject().L = locality
        req.get_subject().O = organization
        req.get_subject().OU = organizational_unit
        x509_extensions = ([])
        sans_list = []
        for san in subject_alternative_name:
            sans_list.append("DNS: {0}".format(san))

        sans_list = ", ".join(sans_list).encode()

        if sans_list:
            x509_extensions.append(crypto.X509Extension("subjectAltName".encode(), False, sans_list))

        req.add_extensions(x509_extensions)
        req.set_pubkey(keypair)
        req.sign(keypair, "sha256")

        key = crypto.dump_privatekey(crypto.FILETYPE_PEM, keypair)
        csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

        certificate = Certificate(csr=csr,author=current_user,cn=common_name,organization=organization,key=key)
        db.session.add(certificate)
        db.session.commit()
        
        #response = b'\n'.join([csr, key])
        csr_io =BytesIO(csr)
        csr_io.seek(0)
        return render_template('csr.html', csr=csr, key=key, csr_file=csr_io)
        #return send_file(csr_io,download_name='csr.pem', mimetype='text/plain', as_attachment=True )
        ##return Response(response, mimetype='text/plain')


    return render_template("generate_csr.html", title='Generate CSR', form=form)

@app.route("/download_certificate", methods=["GET", "POST"])
@login_required
def download_certificate():
    form = CertForm()
    if form.validate_on_submit():
        # Get form data
        data = request.form
        common_name = data['common_name']
        csr = data['csr']
        password = data['password']
        #signed_request = request.files["signed_request"].read()
        
        # Load the signed certificate
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, csr)
        
        # Get the private key from the database
        cursor = cnx.cursor()
        select_query = "SELECT key FROM Certificate WHERE username = %s AND common_name = %s"
        cursor.execute(select_query, (session["username"], cert.get_subject().CN))
        result = cursor.fetchone()
        encrypted_key = result[0]
        
        # Decrypt the private key
        private_key_pem = cipher_suite.decrypt(encrypted_key).decode("utf-8")
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_pem)
        
        # Create a PFX file
        pfx = crypto.PKCS12()
        pfx.set_certificate(cert)
        pfx.set_privatekey(private_key)
        
        # Return the PFX file to the user
        response = make_response(pfx.export())
        response.headers["Content-Disposition"] = "attachment; filename=certificate.pfx"
        response.headers["Content-Type"] = "application/x-pkcs12"
        return response
        
    return render_template("download_certificate.html", title='Generate Certificate', form=form)

@app.route('/certificate/<int:id>/download')
@login_required
def download_csr(id):
    cert = Certificate.query.get_or_404(id)
    file_data = cert.csr
    # Create an in-memory file-like object
    file_stream = BytesIO(file_data)
    # Set the file stream's position to the beginning
    file_stream.seek(0)
    # Return the file as an attachment
    filename = cert.cn + '.csr'
    response = make_response(file_stream.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename={}'.format(filename)
    response.mimetype = 'text/plain'
    return response

@app.route('/key/<int:id>/download')
@login_required
def download_key(id):
    key = Certificate.query.get_or_404(id)
    file_data = key.key
    # Create an in-memory file-like object
    file_stream = BytesIO(file_data)
    # Set the file stream's position to the beginning
    file_stream.seek(0)
    # Return the file as an attachment
    filename = key.cn + '.key'
    response = make_response(file_stream.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename={}'.format(filename)
    response.mimetype = 'text/plain'
    return response

@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    certificates = user.certificates.order_by(Certificate.timestamp.desc())
    return render_template('user.html', title='User Table', user=user, certificates=certificates)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username, current_user.email)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('profile_updated'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)

@app.route('/profile_updated', methods=['GET'])
@login_required
def profile_updated():
    if request.referrer and request.referrer.endswith('/edit_profile'):
        return render_template('profile_updated.html', title='Profile Updated')
    elif request.referrer and request.referrer.endswith('/reset_password_request'):
        return render_template('profile_updated.html', title='Password Updated')
    else:
        return redirect(url_for('index'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
@login_required
def reset_password_request():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.old_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('profile_updated'))
        else:
            flash('Invalid old password.')
    return render_template('reset_password_request.html', title='Reset Password', form=form)