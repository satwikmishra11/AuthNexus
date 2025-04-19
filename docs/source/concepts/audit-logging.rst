Audit Logging System
====================

Log Structure
-------------
.. code-block:: json

   {
       "timestamp": "2023-12-20T14:30:00Z",
       "event_type": "authentication",
       "user_id": "user_123",
       "risk_score": 0.42,
       "client_ip": "192.168.1.100",
       "metadata": {
           "auth_method": "webauthn",
           "device_id": "a1b2c3d4"
       }
   }

Retention Policies
------------------
.. list-table:: 
   :widths: 30 50 20
   :header-rows: 1

   * - Data Type
     - Description
     - Retention
   * - Authentication Logs
     - Successful/Failed attempts
     - 90 days
   * - Audit Trails
     - Configuration changes
     - 1 year
   * - Risk Assessments
     - Detailed risk analysis
     - 6 months
