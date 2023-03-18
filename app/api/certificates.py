from flask import jsonify, request, url_for, abort, g, make_response
from flask_login import current_user
from OpenSSL import crypto
from datetime import datetime
import base64
from app import db
from app.models import User, Certificate
from app.api import bp
from app.api.auth import token_auth
from app.api.errors import bad_request

@bp.route('/generate_csr', methods=['POST'])
@token_auth.login_required
def generate_csr():
    if not request.json:
        abort(400, 'Invalid request data')

    data = request.json
    country = data.get('country', "CH")
    state = data.get('state', "Bern")
    locality = data.get('locality', "Bern")
    organization = data.get('organization')
    organizational_unit = data.get('organizational_unit', '')
    common_name = data.get('common_name')
    subject_alternative_name = data.get('subject_alternative_name', [])

    # Check if country is valid
    if not country or len(country) != 2:
        abort(400, 'Invalid Country')

    # Check if common name has less than 64 characters
    if len(common_name) > 64:
        abort(400, 'Common name must be 64 characters or fewer')

    # Check if common name has less than 64 characters
    if len(organization) > 64:
        abort(400, 'organization must be 64 characters or fewer')

    # Check if all fields are present
    if not all([organization, common_name]):
        abort(400, 'Missing required fields')

    # Check if CSR with common name already exists
    existing_csr = Certificate.query.filter_by(cn=common_name, user_id=g.user.id).first()
    if existing_csr:
        abort(400, f"A certificate with common name '{common_name}' already exists.")

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
    x509_extensions = []
    for san in subject_alternative_name:
        x509_extensions.append(crypto.X509Extension("subjectAltName".encode(), False, f"DNS:{san}".encode()))

    req.add_extensions(x509_extensions)
    req.set_pubkey(keypair)
    req.sign(keypair, "sha256")

    key = crypto.dump_privatekey(crypto.FILETYPE_PEM, keypair)
    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

    certificate = Certificate(csr=csr, author=g.user, cn=common_name, organization=organization, key=key)
    db.session.add(certificate)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'data': {
            'common_name': common_name,
            'csr': csr.decode('utf-8'),
            'key': key.decode('utf-8'),
        }
    })

@bp.route('/certificates', methods=['GET'])
@token_auth.login_required
def get_certificates():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    user_certificates = Certificate.query.filter_by(user_id=g.user.id).order_by(Certificate.id.desc())
    certificates = user_certificates.paginate(page=page, per_page=per_page, error_out=False)
    data = {
        'items': [cert.to_dict() for cert in certificates.items],
        '_meta': {
            'page': page,
            'per_page': per_page,
            'total_pages': certificates.pages,
            'total_items': certificates.total
        },
        '_links': {
            'self': url_for('api.get_certificates', page=page, per_page=per_page),
            'next': url_for('api.get_certificates', page=certificates.next_num, per_page=per_page) if certificates.has_next else None,
            'prev': url_for('api.get_certificates', page=certificates.prev_num, per_page=per_page) if certificates.has_prev else None
        }
    }
    return jsonify(data)

@bp.route('/download/key/<cn>', methods=['GET'])
@token_auth.login_required
def get_certificate_key(cn):
    certificate = Certificate.query.filter_by(cn=cn, user_id=g.user.id).first_or_404()
    return jsonify({
        'key': certificate.key.decode(),
        '_links': {
            'self': url_for('api.get_certificate_key', cn=cn)
        }
    })

@bp.route('/download/csr/<cn>', methods=['GET'])
@token_auth.login_required
def get_certificate_csr(cn):
    certificate = Certificate.query.filter_by(cn=cn, user_id=g.user.id).first_or_404()
    return jsonify({
        'csr': certificate.csr.decode(),
        '_links': {
            'self': url_for('api.get_certificate_csr', cn=cn)
        }
    })

@bp.route('/download/pfx/<cn>', methods=['GET'])
@token_auth.login_required
def download_pfx(cn):
    cert = Certificate.query.filter_by(cn=cn, user_id=g.user.id).first_or_404()

    if not cert.pfx:
        return jsonify({'error': 'No PFX file found for this certificate.'}), 404

    pfx_data_b64 = base64.b64encode(cert.pfx).decode('utf-8')

    return jsonify({
        'status': 'success',
        'data': {
            'pfx': pfx_data_b64,
        }
    })

@bp.route('/convert_certificate', methods=['POST'])
def convert_certificate():
    if not request.json:
        abort(400, 'Invalid request data')

    data = request.json
    private_key = data.get('private_key')
    public_key = data.get('public_key')
    passphrase = data.get('passphrase')

    if not all([private_key, public_key, passphrase]):
        abort(400, 'Missing required fields')
    
    try:
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, public_key)
        pfx = crypto.PKCS12()
        pfx.set_privatekey(pkey)
        pfx.set_certificate(cert)
        pfxdata = pfx.export(passphrase=passphrase)
        # Convert pfx_data to a Base64-encoded string
        pfx_data_b64 = base64.b64encode(pfxdata).decode('utf-8')
    except Exception as e:
        abort(400, f'Invalid certificate or private key: {e}')
    
    return jsonify({
        'status': 'success',
        'data': {
            'pfx': pfx_data_b64,
        }
    })

@bp.route('/download/pfx', methods=['POST'])
@token_auth.login_required
def download_pfx_from_cert():
    if not request.json:
        abort(400, 'Invalid request data')
    
    data = request.json
    cn = data.get('cn')
    certificate = data.get('certificate')
    passphrase = data.get('passphrase')

    existing_key = Certificate.query.filter_by(cn=cn, user_id=g.user.id).first()
    private_key = existing_key.key
    if not existing_key:
        abort(400, 'The Private Key for the Common Name in the CSR does not exist in the database')

    try:
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        pfx = crypto.PKCS12()
        pfx.set_privatekey(pkey)
        pfx.set_certificate(cert)
        pfx_data = pfx.export(passphrase=passphrase)
        existing_key.pfx = pfx_data
        db.session.commit()
        # Convert pfx_data to a Base64-encoded string
        pfx_data_b64 = base64.b64encode(pfx_data).decode('utf-8')

    except Exception as e:
        abort(400, f'Invalid certificate or private key: {e}')


    return jsonify({
        'status': 'success',
        'data': {
            'pfx': pfx_data_b64,
        }
    })