#!/usr/bin/env python3
import unittest
from flask import url_for
from app import create_app, db
from app.models import User, Certificate
from config import Config
import os
import re
import tempfile

class TestConfig(Config):
    TESTING = True
    SERVER_NAME = 'localhost:5000'
    APPLICATION_ROOT = '/'
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class MainBlueprintTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.user = User(username='testuser', email='test@example.com', password_hash='password')

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_hashing(self):
        u = User(username='wronguser')
        u.set_password('cat')
        self.assertFalse(u.check_password('dog'))
        self.assertTrue(u.check_password('cat'))

    def test_generate_csr_route(self):
        with self.client:
            # Login to the application
            self.client.post(url_for('auth.login'), data={'username': 'testuser', 'password': 'password'})

            # Generate a CSR
            data = {
                'country': 'CH',
                'state': 'Bern',
                'locality': 'Bern',
                'organization': 'Test Organization',
                'organizational_unit': '',
                'common_name': 'test.com',
                'subject_alternative_name': 'test1.com,test2.com'
            }

            response = self.client.post(url_for('main.generate_csr'), data=data, follow_redirects=True)
            self.assertEqual(response.status_code, 200)


    def test_generate_csr_route_without_login(self):
        response = self.client.get(url_for('main.generate_csr'))
        self.assertEqual(response.status_code, 302)

if __name__ == '__main__':
    unittest.main(verbosity=2)