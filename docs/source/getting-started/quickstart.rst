Quick Start Guide
================

Basic Authentication Flow
-------------------------
.. code-block:: python

   from authnexus import AuthNexus, SecurityConfig

   # Initialize with security settings
   config = SecurityConfig(risk_threshold=0.75)
   auth = AuthNexus(secret_key="your-secret-key", security=config)

   # Generate JWT token
   token = auth.create_token(
       user_id="user_123",
       metadata={"role": "admin"}
   )

   # Verify token
   try:
       payload = auth.verify_token(token)
       print(f"Authenticated user: {payload['sub']}")
   except SecurityThresholdExceeded as e:
       print(f"Security violation: {e}")
