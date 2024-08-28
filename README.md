## Tesla Vehicle Command (CPP/Arduino) / TeslaBLE

This library is the successor of the [TeslaBLE](https://github.com/pmdroid/tesla-ble) library. Tesla vehicles now
support a new protocol that ensures secure,
end-to-end command authentication.
This C++ and Arduino library uses this protocol to control vehicle functions, such as climate control and charging.

It is available under the terms of the GNU Affero General Public License (AGPL), with an option for businesses to
purchase a commercial license.

### Initialization

To begin using the TeslaBLE library, create instances of `Authenticator` and `Session`.

```c++
TeslaBLE::Authenticator authenticator;
TeslaBLE::Session session;
```

### Private Key

A private key is essential for communication with the Tesla vehicle. You can either load an existing key or generate a
new one. This key must be securely stored for future use.

```c++
unsigned char private_key[227] =
    "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----";

client.LoadPrivateKey(private_key, sizeof private_key);
```

If the private key hasn't been whitelisted with the car, generate a whitelist message and send it. Be aware that the car
may require NFC card confirmation or display a UI prompt.

```c++
authenticator.BuildKeyWhitelistMessage(Keys_Role_ROLE_OWNER, sessionInfoRequestBuffer,
                                      &sessionInfoRequestBufferLength);
```

**Upon message transmission, the vehicle will return an OperationStatus_E enumeration:**

* **OPERATIONSTATUS_OK:** Operation successful.
* **OPERATIONSTATUS_WAIT:** Vehicle awaiting NFC card presentation.
* **OPERATIONSTATUS_ERROR:** Operation failed.

**A `OPERATIONSTATUS_WAIT` response indicates that the NFC card has not yet been presented to the vehicle.**

### Session Setup

To utilize the `Session`, provide the Vehicle Identification Number (VIN), routing address, and loaded `Authenticator`.
The Session class will track essential data such as counter, epoch, and the vehicle's current time.

```c++
unsigned char vin[18]; // XP7YGCEL9NB000000
strcpy((char *) vin, "XP7YGCEL9NB000000");

session.SetVIN(vin);
session.GenerateRoutingAddress(); // Or session.SetRoutingAddress()
session.LoadAuthenticator(&authenticator);
```

To conserve memory, a single Authenticator instance is shared among all system domains. This instance stores the
exchanged secret essential for message encryption.

### Obtaining Session Information

**Prior to transmitting any messages to the vehicle, it is imperative to obtain the latest session information by
constructing and dispatching a `RequestSessionInfo` message.** The acquired session data should be retained for
subsequent interactions. It is essential to note that the vehicle may provide updated session details, particularly
following software revisions.

```c++
unsigned char securitySessionInfoRequestBuffer[200];
size_t securitySessionInfoRequestBufferLength = 0;

session.BuildRequestSessionInfoMessage(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
                                             securitySessionInfoRequestBuffer,
                                             &sessionInfoRequestBufferLength);

session.UpdateSessionInfo(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, session_info, 92);
```

This command exports the session data to the specified session_buffer and populates the session_size variable with the
exported data's length.

```c++
session.ExportSessionInfo(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, session_buffer,
                                                &session_size);
```

### Sending Commands

To execute commands on the car:

1. Use the `CarServer` or `Security` class to construct the appropriate command message.
2. Encapsulate the command message within a `RoutableMessage` using the `BuildRoutableMessage` function.
3. Send the resulting `RoutableMessage` to the car.

```c++
TeslaBLE::CarServer::TurnOnClimate(action_message_buffer, &action_message_buffer_size);

size_t output_message_buffer_size = 0;
unsigned char output_message_buffer[UniversalMessage_RoutableMessage_size];

session.BuildRoutableMessage(domain, action_message_buffer,
                                   action_message_buffer_size, output_message_buffer,
                                   &output_message_buffer_size);
```

The `BuildRoutableMessage` function processes the message by encrypting its content, computing a checksum for integrity,
and prepending the message length. The resulting output is a transmission-ready message formatted for the vehicle.

## Protocol Details

For a deeper understanding of the protocol, please refer to the official
documentation: [vehicle-command](https://github.com/teslamotors/vehicle-command/blob/main/pkg/protocol/protocol.md).

## Expanding Functionality

While not all `VehicleAction` commands are currently implemented, adding new functionality is straightforward. Simply
incorporate additional commands into the `carserver.cpp` class, following the established pattern of existing commands.

## Protocol Buffers (Protobuf)

**Updating Protobuf Files:**

1. Download the latest Protobuf files from the Tesla vehicle-command project on GitHub.
2. Navigate to the library's root directory and execute the `proto.sh` shell script.

**Important Considerations:**

* Tesla may occasionally remove fields from messages, potentially causing compatibility issues. Remain vigilant for
  updates.
* Advanced users can customize Protobuf generation through the `.options` files. Refer to the documentation for more
  information: [here](https://jpa.kapsi.fi/nanopb/docs/reference.html#generator-options)

### Troubleshooting Protobuf Generation Issues

**Potential Causes:**

* **Missing nanopb installation:** Ensure nanopb is installed correctly by running `pip install nanopb`.
* **Incorrect PATH environment variable:** Verify that the `PATH` variable includes the directory containing
  the `protoc` executable. Use the following command to add it to your `.bashrc` file (adjust for zsh if necessary):

```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

**Additional Tips:**

* Consider using a virtual environment to isolate project dependencies.
* Check for any conflicting installations of `protoc` or `nanopb`.
* Verify that the protobuf files are formatted correctly.
* Refer to the nanopb documentation for more in-depth troubleshooting guidance.

## Examples

The library includes two example projects demonstrating direct car communication:

### Simple Example

This example can be executed on a standard computer. To build and run:

1. Navigate to the `examples/simple` directory.
2. Create a build directory: `mkdir -p build`
3. Change to the build directory: `cd build`
4. Generate build files using CMake: `cmake ..`
5. Compile the project: `make`

### ESP32 Example

This example requires a Seeed Studio XIAO ESP32C3 board and the PlatformIO development environment. Detailed
instructions for setting up PlatformIO and configuring the project are available in the `examples/esp32` directory.

## Arduino Example: Automated Setup with `arduino.sh` Script

**Automated Setup with `arduino.sh` Script**

The Arduino example offers a convenient way to interact with your car, potentially through an automated setup script
called `arduino.sh`. This script likely handles the following tasks:

* **mbedtls Downgrade (Caution Advised):** Be aware that downgrading mbedTLS is not recommended due to security
  concerns. Consider exploring alternative approaches that support newer mbedTLS versions.
* **Custom Library Creation:** The script might create a library file (`.zip`) compatible with the Arduino IDE. This
  library likely provides essential functionalities for communication with the car.
* **Dependency Management:** It might manage the installation of additional dependencies such as nanopb version 0.4.8
  and the NimBLE library.

**Important Considerations:**

* **Security Risks:** Downgrading mbedTLS can expose your vehicle to security vulnerabilities. Prioritize secure
  solutions whenever possible.

**Utilizing `arduino.sh` (if applicable):**

1. Ensure you understand the potential security risks associated with downgrading mbedTLS.
2. Review the script's functionality (if possible) to understand the steps it performs.
3. Execute the script according to its instructions (likely by running `./arduino.sh` in the terminal).

## License

This project is dual-licensed under:

1. **GNU General Public License (AGPL) v3.0 or later**:  
   Under this license, you are free to use, modify, and distribute the software, provided that any modifications or
   derivative works are also licensed under the GPL and the source code is made available.

   For the full text of the AGPL v3.0, see the [LICENSE](./LICENSE.md) file in this repository.

2. **Commercial License**:  
   For organizations or individuals who wish to use this software in a proprietary product or without adhering to the
   terms of the AGPL, a commercial license is available.

   Please contact us at [me@pascal.sh](mailto://me@pascal.sh) for more information on purchasing a commercial
   license.

## Commercial License Information

If you would like to use Tesla Vehicle Command (CPP/Arduino) in a commercial environment without the restrictions of the
AGPL, you can purchase
a commercial license. This license allows you to integrate Tesla Vehicle Command (CPP/Arduino) into your proprietary
applications without the
need to disclose your source code or comply with the AGPL's copyleft requirements.

## Contact

For questions, support, or to inquire about a commercial license, please contact:

- **Email**: [me@pascal.sh](mailto:me@pascal.sh)
- **Website**: [https://pascal.sh](https://pascal.sh)

# IMPORTANT

Please take note that this library does not have official backing from Tesla, and its operational capabilities may be
discontinued without prior notice. It's essential to recognize that this library retains private keys and other
sensitive data on your device without encryption. I would like to stress that I assume no liability for any possible (
although highly unlikely) harm that may befall your vehicle.

