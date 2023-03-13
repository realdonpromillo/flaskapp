from flask import jsonify, request, url_for, abort
from app import db
from app.models import Certificate
from app.api import bp
from app.api.auth import token_auth
from app.api.errors import bad_request



@bp.route('/users/<username>', methods=['GET'])
def get_user(id):
    pass

@bp.route('/generate_csr', methods=['POST'])
def generate_csr():
    pass

@bp.route('/download/key/<cn>', methods=['GET'])
def get_key(cn):
    pass

@bp.route('/download/csr/<cn>', methods=['GET'])
def get_csr(cn):
    pass

@bp.route('/download/pfx/<cn>', methods=['GET'])
def get_pfx(cn):
    pass
