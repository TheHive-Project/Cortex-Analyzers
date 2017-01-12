from setuptools import setup

setup(
    name='cortexutils',
    version='1.0.0',
    description='Cortext Python utilities package',
    author='TheHive-Project',
    author_email='support@thehive-project.org',
    url='https://github.com/CERT-BDF/Cortex-Analyzers/tree/master/contrib',
    py_modules=['cortexutils.analyzer'],
    install_requires=[
        'ioc-parser'
    ]
)
