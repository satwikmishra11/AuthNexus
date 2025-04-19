Security Best Practices
=======================

Secret Management
-----------------
.. code-block:: yaml

   # Recommended .env configuration
   AUTH_SECRET=your-256bit-secret
   ENCRYPTION_KEYS=rotation-schedule:weekly

Certificate Rotation
--------------------
.. code-block:: bash

   # Rotate cryptographic keys
   authnexus-cli rotate-keys --algorithm ECDSA-P384

Security Headers
----------------
.. code-block:: python

   # FastAPI security middleware example
   from authnexus.security import SecurityHeadersMiddleware
   app.add_middleware(SecurityHeadersMiddleware)
