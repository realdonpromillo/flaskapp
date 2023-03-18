#!/usr/bin/env python3
import unittest
from flask import url_for
from app import create_app, db
from app.models import User, Certificate
from config import config

class TestConfig(config):
    TESTING = True
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
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_hashing(self):
        u = User(username='wronguser')
        u.set_password('cat')
        self.assertFalse(u.check_password('dog'))
        self.assertTrue(u.check_password('cat'))

    def test_index_route(self):
        response = self.client.get(url_for('main.index'))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Home Page', response.data)

    def test_generate_csr_route(self):
        with self.client:
            self.client.post(url_for('auth.login'), data={'username': 'testuser', 'password': 'password'})
            response = self.client.get(url_for('main.generate_csr'))
            self.assertEqual(response.status_code, 200)

            data = {
                'country': 'CH',
                'state': 'Bern',
                'locality': 'Bern',
                'organization': 'Test Organization',
                'organizational_unit': '',
                'common_name': 'test.com',
                'subject_alternative_name': 'test1.com,test2.com'
            }

            response = self.client.post(url_for('main.generate_csr'), data=data)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'test.com', response.data)

    def test_download_certificate_route(self):
        with self.client:
            self.client.post(url_for('auth.login'), data={'email': 'test@example.com', 'password': 'password'})
            csr = Certificate(author=self.user, cn='test.com', organization='Test Organization', csr='test csr', key='test key')
            db.session.add(csr)
            db.session.commit()

            data = {
                'common_name': 'test.com',
                'certificate': 'test cert',
                'password': 'test password'
            }

            response = self.client.post(url_for('main.download_certificate'), data=data)
            self.assertEqual(response.status_code, 200)