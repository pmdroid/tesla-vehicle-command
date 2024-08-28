## TeslaBLE::Session Class

### Overview
The `TeslaBLE::Session` class appears to manage session-related data and operations for Tesla BLE communication. It handles session information, metadata generation, authentication, and message construction.

### Key Components and Responsibilities
* **Session Data:** Manages session-specific data for different domains, including time zeros, counters, epochs, clock times, car keys, and car key sizes.
* **Metadata:** Instantiates a `MetaData` object for generating metadata.
* **Authentication:** Collaborates with an `Authenticator` object for authentication tasks.
* **Message Construction:** Builds routable and action messages, as well as request session info messages.

### Public Methods

* **LoadAuthenticator:** Sets the `authenticator_` member to the provided `Authenticator` object.
* **LoadPrivateKey:** Loads a private key for authentication purposes.
* **LoadPrivateKeyContext:** Loads a pre-initialized MbedTLS private key context.
* **GenerateRoutingAddress:** Generates a routing address.
* **SetRoutingAddress:** Sets the routing address manually.
* **UpdateSessionInfo:** Updates session information for a specific domain.
* **BuildRoutableMessage:** Builds a routable message for a given domain and action message.
* **BuildActionMessage:** Builds an action message based on a `CarServer_VehicleAction` structure.
* **BuildRequestSessionInfoMessage:** Builds a request session info message for a given domain.
* **ExpiresAt:** Calculates the expiration time for a given domain and expiration time in seconds.
* **Counter:** Returns the counter for a given domain.
* **Epoch:** Returns the epoch for a given domain.
* **SetVIN:** Sets the vehicle identification number (VIN).
* **ExportSessionInfo:** Exports session information for a given domain.
