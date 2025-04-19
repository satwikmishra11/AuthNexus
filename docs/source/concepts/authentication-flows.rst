Authentication Flows
====================

WebAuthn Flow
------------
.. mermaid::
   :caption: Passwordless Authentication Sequence

   sequenceDiagram
       User->>Client: Initiate Registration
       Client->>AuthNexus: Get Challenge
       AuthNexus->>Client: Registration Options
       Client->>Authenticator: Create Credential
       Authenticator->>Client: Public Key
       Client->>AuthNexus: Verify Registration
       AuthNexus->>Database: Store Credential

OAuth 2.1 Flow
--------------
.. graphviz::

   digraph oauth_flow {
       rankdir=LR;
       User -> Client [label="1. Request Auth"];
       Client -> AuthServer [label="2. Redirect"];
       User -> AuthServer [label="3. Authenticate"];
       AuthServer -> Client [label="4. Authorization Code"];
       Client -> AuthNexus [label="5. Exchange Code"];
       AuthNexus -> ResourceServer [label="6. Access Token"];
   }
