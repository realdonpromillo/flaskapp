from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length
from app.models import User, Certificate

# Eigenentwickliung
class CSRForm(FlaskForm):
    country = StringField('Country', validators=[DataRequired(), Length(min=2, max=2)], default='CH')
    # Eigenentwickelte Validatoren
    state = SelectField('State', validators=[DataRequired()], default = 'Bern',choices = [
        ('Aargau', 'Aargau'),
        ('Appenzell Ausserrhoden', 'Appenzell Ausserrhoden'),
        ('Appenzell Innerrhoden', 'Appenzell Innerrhoden'),
        ('Basel-Landschaft', 'Basel-Landschaft'),
        ('Basel-Stadt', 'Basel-Stadt'),
        ('Bern', 'Bern'),
        ('Fribourg', 'Fribourg'),
        ('Geneva', 'Geneva'),
        ('Glarus', 'Glarus'),
        ('Graubünden', 'Graubünden'),
        ('Jura', 'Jura'),
        ('Luzern', 'Luzern'),
        ('Neuchâtel', 'Neuchâtel'),
        ('Nidwalden', 'Nidwalden'),
        ('Obwalden', 'Obwalden'),
        ('Schaffhausen', 'Schaffhausen'),
        ('Schwyz', 'Schwyz'),
        ('Solothurn', 'Solothurn'),
        ('St. Gallen', 'St. Gallen'),
        ('Ticino', 'Ticino'),
        ('Uri', 'Uri'),
        ('Valais', 'Valais'),
        ('Vaud', 'Vaud'),
        ('Zug', 'Zug'),
        ('Zürich', 'Zürich'),
    ] )
    # Eigenentwickelte Validatoren
    locality = SelectField('Locality', validators=[DataRequired()], default = 'Bern',choices = [
        ('Aargau', 'Aargau'),
        ('Appenzell Ausserrhoden', 'Appenzell Ausserrhoden'),
        ('Appenzell Innerrhoden', 'Appenzell Innerrhoden'),
        ('Basel-Landschaft', 'Basel-Landschaft'),
        ('Basel-Stadt', 'Basel-Stadt'),
        ('Bern', 'Bern'),
        ('Fribourg', 'Fribourg'),
        ('Geneva', 'Geneva'),
        ('Glarus', 'Glarus'),
        ('Graubünden', 'Graubünden'),
        ('Jura', 'Jura'),
        ('Luzern', 'Luzern'),
        ('Neuchâtel', 'Neuchâtel'),
        ('Nidwalden', 'Nidwalden'),
        ('Obwalden', 'Obwalden'),
        ('Schaffhausen', 'Schaffhausen'),
        ('Schwyz', 'Schwyz'),
        ('Solothurn', 'Solothurn'),
        ('St. Gallen', 'St. Gallen'),
        ('Ticino', 'Ticino'),
        ('Uri', 'Uri'),
        ('Valais', 'Valais'),
        ('Vaud', 'Vaud'),
        ('Zug', 'Zug'),
        ('Zürich', 'Zürich'),
    ] )
    organization = StringField('Organization', validators=[DataRequired()])
    organizational_unit = StringField('Organizational Unit')
    common_name = StringField('Common Name', validators=[DataRequired()])
    subject_alternative_name = StringField('Subject Alternative Name')
    submit = SubmitField('Generate CSR')

# Eigenentwickliung
class CertForm(FlaskForm):
    common_name = StringField('Common Name', validators=[DataRequired()])
    certificate = TextAreaField('Certificate', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Generate P12')

# Übernommen aus den Beispielen von Miguel Grinberg
class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')

    def __init__(self, original_username, original_email, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user is not None:
                raise ValidationError('Please use a different email address.')

# Eigenentwickliung
class ConvertCertificateForm(FlaskForm):
    private_key = TextAreaField('Private Key', validators=[DataRequired()])
    public_key = TextAreaField('Public Key', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')