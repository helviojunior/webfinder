#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from setuptools import setup, find_packages

version = {}
with open('webfinder/version.py') as f:
    exec(f.read(), version)

setup(name='webfinder',
      version=version['__version__'],
      description='Automated web server finder',
      author='Hélvio Junior (M4v3r1ck)',
      author_email='helvio_junior@hotmail.com',
      url='https://github.com/helviojunior/webfinder',
      packages=find_packages(),
      package_data={'webfinder': ['resources/*']},
      install_requires=['bs4>=0.0.1', 'requests>=2.23.0', 'colorama'],
      entry_points= { 'console_scripts': [
        'webfinder=webfinder.webfinder:run',
        ]}
      )