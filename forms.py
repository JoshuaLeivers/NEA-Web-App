from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField, HiddenField, BooleanField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, Length, EqualTo, InputRequired


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    token = StringField("Token")
    submit = SubmitField("Sign In")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(1, 64, message="Username must be between "
                                                                                          "1-64 characters in "
                                                                                          "length.")])
    submit = SubmitField("Register")


class RegisterConfirmForm(FlaskForm):
    req_id = HiddenField("Request",
                         validators=[DataRequired(), Length(64, 64, "Account request IDs must be 64 characters long.")])
    password = PasswordField("Password", validators=[DataRequired(), Length(10, 72, message="Passwords must be "
                                                                                            "between 10 and 72 "
                                                                                            "characters long.")])
    password_confirm = PasswordField("Confirm Password", validators=[DataRequired(),
                                                                     EqualTo("password",
                                                                             "Password and confirm password fields must"
                                                                             " be the same.")])
    tfa = BooleanField("Setup Two Factor Authentication?", default=True)
    submit = SubmitField("Confirm")


class RegisterConfirmCodeForm(FlaskForm):
    req_id = StringField("Code", validators=[DataRequired(), Length(64, 64)])
    submit = SubmitField("Confirm")


class RegisterTFAForm(FlaskForm):
    token = StringField("Token", validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField("Verify")


class SearchForm(FlaskForm):
    username = StringField("Username")
    forename = StringField("Forename")
    surname = StringField("Surname")
    class_id = SelectField("Classes")
    submit = SubmitField("Submit")
