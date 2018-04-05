from setuptools import setup

setup(
    name='cortexutils',
    version='1.2.3',
    description='A Python library for including utility classes for Cortex analyzers',
    long_description=open('README').read(),
    author='TheHive-Project',
    author_email='support@thehive-project.org',
    license='AGPL-V3',
    url='https://github.com/TheHive-Project/Cortex-Analyzers/tree/master/contrib',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules'],
    py_modules=[
        'future',
        'cortexutils.analyzer',
        'cortexutils.extractor'
    ],
    install_requires=[],
    test_suite='tests'
)
