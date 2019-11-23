Python JPake
============

|build-status| |coverage|

.. |build-status| image:: https://travis-ci.org/bwhmather/python-jpake.png?branch=develop
    :target: https://travis-ci.org/bwhmather/python-jpake
    :alt: Build Status
.. |coverage| image:: https://coveralls.io/repos/bwhmather/python-jpake/badge.png?branch=develop
    :target: https://coveralls.io/r/bwhmather/python-jpake?branch=develop
    :alt: Coverage

.. begin-docs

Python implementation of the J-PAKE password authenticated key agreement algorithm.

Written with reference to `warner/python-jpake <https://github.com/warner/python-jpake>`_ but makes use of python 3 features and presents a different api.


Installation
------------
.. begin-installation

Recommended method is to use the version from `pypi <https://pypi.python.org/pypi/jpake>`_:

.. code:: bash

    $ pip install jpake

Please note that this library only supports python versions 3.4 and later.

.. end-installation


Usage
-----
.. begin-usage

Basic usage demonstrating how to securely generate two copies of the same key in a single process:

.. code:: python

    secret = "1234"
    alice = JPAKE(secret=secret, signer_id=b"alice")
    bob = JPAKE(secret=secret, signer_id=b"bob")

    alice.process_one(bob.one())
    bob.process_one(alice.one())

    alice.process_two(bob.two())
    bob.process_two(alice.two())

    self.assertEqual(alice.K, bob.K)


More complete example:

.. code:: python

    def client_main():
        # Request that the server start a new connection.
        session_id = send_start_session()

        # Obtain a copy of the secret through the side-channel.
        secret = get_via_sidechannel()

        jpake = JPAKE(secret=secret, signer_id=b"client")

        server_one = send_handshake_phase_one(session_id, jpake.one())

        jpake.process_one(
            remote_gx1=server_one['gx1'], remote_zkp_x1=server_one['zkp_x1'],
            remote_gx2=server_one['gx2'], remote_zkp_x2=server_one['zkp_x2'],
        )

        server_two = send_handshake_phase_two(session_id, jpake.two())
        jpake.process_two(
            remote_A=server_two['A'], remote_zkp_A=server_two['zkp_A'],
        )

        send_secret_message("hello world", key=jpake.K)


    def handle_start_session()
        session_id = generate_session_id()
        secret = generate_secret()

        db.put('secrets', session_id, secret)

        # Return the secret to the user via a trusted sidechannel.
        # DO NOT return the secret as a response, as doing so defeats the whole
        # purpose of the exercise.
        send_via_sidechannel(secret)

        return session_id

    def handle_handshake_phase_one(session_id, client_one):
        # Load the shared secret from the datastore.
        secret = db.get('secrets', session_id)

        # Create a new JPAKE handshake object.
        jpake = JPAKE(secret=secret, signer_id="server")

        session.process_one(
            remote_gx1=client_one['gx1'], remote_zkp_x1=client_one['zkp_x1'],
            remote_gx2=client_one['gx2'], remote_zkp_x2=client_one['zkp_x2'],
        )

        # Save the important bits of the handshake to the db so that we can
        # restore it when we receive step 2.
        db.put('handshakes', session_id, {
            # Generated locally.
            'x1': session.x1,
            'x2': session.x2,
            # Sent by the client.
            'remote_gx1': session.remote_gx1,
            'remote_gx2': session.remote_gx2,
        })

        return session.one()

    def handle_handshake_phase_two(handshake_id, client_two):
        # Reload the jpake handshake object from the db
        db.get
        jpake = JPAKE(
            x1=handshake['x3'], x=session['x4'],
            gx3=handshake['gx1'], gx4=handshake['gx2'],
            verify=False,
        )

        # Check the details sent by the client
        session.process_two(B=client_one['A'], zkp_B=client_one['zkp_A'])

        # Save to the database


    def handle_secret_message(message):
        pass


.. end-usage


Links
-----

- Source code: https://github.com/bwhmather/python-jpake
- Issue tracker: https://github.com/bwhmather/python-jpake
- Continuous integration: https://travis-ci.org/bwhmather/python-jpake
- PyPI: https://pypi.python.org/pypi/python-jpake


License
-------

This project is licensed under the BSD 3-clause revised license.
See `LICENSE <./LICENSE>`_ for details.

.. end-docs
