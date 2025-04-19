Risk Assessment Engine
======================

Risk Factors
------------
.. list-table:: Risk Calculation Matrix
   :widths: 25 50 25
   :header-rows: 1

   * - Factor
     - Description
     - Weight
   * - IP Reputation
     - Known malicious IP detection
     - 0.3
   * - Velocity
     - Requests per minute
     - 0.25
   * - Device Fingerprint
     - Browser/OS anomalies
     - 0.2
   * - Behavior Patterns
     - Usage deviations
     - 0.25

Configuration
-------------
.. code-block:: python

   from authnexus.risk import RiskProfile

   profile = RiskProfile(
       ip_velocity_window=300,  # 5 minutes
       max_failed_attempts=5,
       geo_fencing=True
   )
