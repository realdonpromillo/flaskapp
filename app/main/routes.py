from datetime import datetime
from flask import render_template, flash, redirect, url_for, make_response, send_file, Response, abort, request, jsonify, current_app
from flask_login import current_user, login_required
from app import db
from app.main.forms import CSRForm, CertForm, EditProfileForm, ConvertCertificateForm
from app.models import User, Certificate
from OpenSSL import crypto
from app.main import bp
from OpenSSL import SSL
import base64
from io import BytesIO

#Übernommen aus den Beispielen von Miguel Grinberg
@bp.route('/')
@bp.route('/index')
@login_required
def index():
    return render_template("index.html", title='Home Page')

# Eigenentwicklung
@bp.route("/generate_csr", methods=["GET", "POST"])
@login_required
def generate_csr():
    form = CSRForm()
    if form.validate_on_submit():
        # Set default values for optional fields
        organizational_unit = ""
        # retrieve form data and generate CSR
        data = request.form
        country = data['country']
        state = data['state']
        locality = data['locality']
        organization = data['organization']
        organizational_unit = data['organizational_unit'] or ""
        common_name = data['common_name']
        subject_alternative_name = data['subject_alternative_name']

        # Check if CSR with common name already exists
        existing_csr = Certificate.query.filter_by(cn=common_name, user_id=current_user.id).first()
        if existing_csr:
            flash(f"A certificate with common name '{common_name}' already exists.")
            return render_template("generate_csr.html", title='Generate CSR', form=form, data=data)

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
        if organizational_unit:
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
        return render_template('csr.html', cn=common_name,csr=csr, key=key)


    return render_template("generate_csr.html", title='Generate CSR', form=form)

# Eigenentwicklung
@bp.route("/download_certificate", methods=["GET", "POST"])
@login_required
def download_certificate():
    form = CertForm()
    if form.validate_on_submit():
        try:
            # Load the existing key from the database
            existing_key = Certificate.query.filter_by(cn=form.common_name.data, user_id=current_user.id).first()
            private_key = existing_key.key
            if not existing_key:
                flash('The Private Key for the Common Name in the CSR does not exist in the database')
                return render_template('download_error.html', title='Error')

            certificate = (form.certificate.data)
            passphrase = (form.password.data)
            
            # Load private key
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)

            # Load public key (certificate)
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
            
            # Create PKCS#12 (PFX) file
            pfx = crypto.PKCS12()
            pfx.set_privatekey(pkey)
            pfx.set_certificate(cert)
            pfx_data = pfx.export(passphrase=passphrase)

            # Save the PFX to the database
            existing_key.pfx = pfx_data
            db.session.commit()

            # Return the PFX as a download
            filename = existing_key.cn + '.pfx'
            response = make_response(pfx_data)
            response.headers['Content-Disposition'] = 'attachment; filename={}'.format(filename)
            response.headers.set('Content-Type', 'application/x-pkcs12')
            return response
        
        except Exception as e:
            error_message = str(e)
            return render_template('convert_error.html', title='Error Converting Certificate', error_message=error_message)
               
    return render_template('download_certificate.html', title='Download Certificate', form=form)

# Eigenentwicklung
@bp.route('/convert_certificate', methods=['GET', 'POST'])
def convert_certificate():
    form = ConvertCertificateForm()
    if form.validate_on_submit():
        try:
            # decode the private and public keys from base64 and add padding if needed
            private_key = (form.private_key.data)
            public_key = (form.public_key.data)
            passphrase = (form.password.data)
            
            # Load private key
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)

            # Load public key (certificate)
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, public_key)
            
            # Create PKCS#12 (PFX) file
            pfx = crypto.PKCS12()
            pfx.set_privatekey(pkey)
            pfx.set_certificate(cert)
            pfx_data = pfx.export(passphrase=passphrase)

            # Return the PFX as a download
            response = make_response(pfx_data)
            response.headers.set('Content-Disposition', 'attachment', filename='certificate.pfx')
            response.headers.set('Content-Type', 'application/x-pkcs12')
            return response
        
        except Exception as e:
            error_message = str(e)
            return render_template('convert_error.html', title='Error Converting Certificate', error_message=error_message)
        
    return render_template('convert_certificate.html', title='Convert Certificate', form=form)    

# Eigenentwicklung
@bp.route('/csr/download/<string:cn>')
@login_required
def download_csr(cn):
    csr = Certificate.query.filter_by(cn=cn, user_id=current_user.id).first()
    if csr is None:
        abort(404)
    file_data = csr.csr
    # Create an in-memory file-like object
    file_stream = BytesIO(file_data)
    # Set the file stream's position to the beginning
    file_stream.seek(0)
    # Return the file as an attachment
    filename = csr.cn + '.csr'
    response = make_response(file_stream.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename={}'.format(filename)
    response.mimetype = 'text/plain'
    return response

# Eigenentwicklung
@bp.route('/key/download/<string:cn>')
@login_required
def download_key(cn):
    key = Certificate.query.filter_by(cn=cn, user_id=current_user.id).first()
    if key is None:
        abort(404)
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

# Eigenentwicklung
@bp.route('/pfx/download/<string:cn>')
@login_required
def download_pfx(cn):
    certificate = Certificate.query.filter_by(cn=cn, user_id=current_user.id).first()
    if certificate is None:
        abort(404)
    pfx_data = certificate.pfx
    filename = certificate.cn + '.pfx'
    response = make_response(pfx_data)
    response.headers['Content-Disposition'] = 'attachment; filename={}'.format(filename)
    response.headers.set('Content-Type', 'application/x-pkcs12')
    return response

# Übernommen aus den Beispielen von Miguel Grinberg, ergänzt mit den eigenen Datenbankfeldern
@bp.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    ##certificates = user.certificates.order_by(Certificate.timestamp.desc())
    page = request.args.get('page', 1, type=int)
    certificates = current_user.certificates.order_by(Certificate.timestamp.desc()).paginate(
        page=page, per_page=current_app.config['CERTIFICATES_PER_PAGE'], error_out=False)
    next_url = url_for('main.user', username=user.username, page=certificates.next_num) \
        if certificates.has_next else None
    prev_url = url_for('main.user', username=user.username, page=certificates.prev_num) \
        if certificates.has_prev else None
    return render_template('user.html', title='User Table', user=user, certificates=certificates,
                           next_url=next_url, prev_url=prev_url)

# Übernommen aus den Beispielen von Miguel Grinberg
@bp.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username, current_user.email)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('main.edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)

# Eigenentwicklung
@bp.route('/delete_certificate/<int:id>', methods=['POST'])
@login_required
def delete_certificate(id):
    certificate = Certificate.query.get_or_404(id)
    if certificate.user_id != current_user.id:
        abort(403)
    db.session.delete(certificate)
    db.session.commit()
    flash('Certificate deleted.')
    return redirect(url_for('main.user', username=current_user.username))