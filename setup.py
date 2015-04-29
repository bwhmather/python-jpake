from setuptools import setup, find_packages


setup(
    name='jpake',
    url='github.com/bwhmather/python-jpake',
    version='0.6.0',
    author='Ben Mather',
    author_email='bwhmather@bwhmather.com',
    maintainer='',
    license='BSD',
    description=(
        'Implementation of the J-PAKE password authenticated key agreement '
        'algorithm'
    ),
    long_description=__doc__,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    install_requires=[
    ],
    packages=find_packages(),
    package_data={
        '': ['*.*'],
    },
    test_suite='jpake.tests.suite',
)
