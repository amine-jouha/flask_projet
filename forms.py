from flask_wtf import FlaskForm
from flask import Flask, redirect, g, url_for, render_template, request, session, flash
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, InputRequired



class LoginForm(FlaskForm):
    username = StringField('username',validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')
    



class RegisterForm(FlaskForm):
    username = StringField('username',
                           validators=[InputRequired(), Length(min=2, max=20)])
    email = StringField('email',
                        validators=[InputRequired(), Email(message='Invalid email'), Length(min=8, max=80)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=15)])
    confirm_password = PasswordField('confirmpassword',
                                     validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('sign up')



class ResetRequestForm(FlaskForm):
    email = StringField('email',validators=[InputRequired(), Length(min=4, max=90)])
    submit = SubmitField('Rest Password',validators=[InputRequired()])



class ResetPasswordForm(FlaskForm):
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('confirmpassword',
                                     validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Change Password',validators=[InputRequired()])
    