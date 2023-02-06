from OpenSSL import crypto
from forms import CSRForm

class CsrGenerator(object):
    DIGEST = "sha256"
    DEFAULT_KEYSIZE = 2048

    def generate_csr(): 
        form = CSRForm()
        # Create a key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

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

        req.add_extensions(x509_extenstions)
        req.set_pubkey(key)
        req.sign(key, "sha256")
        return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req).decode()
