from flask import jsonify, request, url_for, abort, g, make_response
from flask_login import current_user
from app import db
from app.models import User, Certificate
from app.api import bp
from app.api.auth import token_auth
from app.api.errors import bad_request

@bp.route('/generate_csr', methods=['POST'])
def generate_csr():
    pass

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

    response = make_response(cert.pfx)
    response.headers.set('Content-Type', 'application/x-pkcs12')
    response.headers.set('Content-Disposition', 'attachment', filename=f'{cn}.pfx')
    return response
