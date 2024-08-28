#include <car_server.pb.h>
#include <authenticator.h>
#include <carserver.h>
#include <shared.h>
#include <functional>
#include <iostream>
#include <metadata.h>
#include <security.h>
#include <session.h>

#include "ble.h"

TeslaBLE::BLE ble = TeslaBLE::BLE(false);
TeslaBLE::Session session = TeslaBLE::Session{};

void message_handler(UniversalMessage_RoutableMessage routable_message) {
    if (routable_message.has_to_destination && routable_message.to_destination.sub_destination.
        domain == UniversalMessage_Domain_DOMAIN_BROADCAST) {
        // printf("Dropping broadcast message\n");

        VCSEC_FromVCSECMessage vcsec_from_vcsec_message = VCSEC_FromVCSECMessage_init_default;
        TeslaBLE::Common::DecodeFromVCSECMessage(routable_message.payload.protobuf_message_as_bytes.bytes,
                                                 routable_message.payload.protobuf_message_as_bytes.size,
                                                 &vcsec_from_vcsec_message);

        // printf("Sub Message: %d\n", vcsec_from_vcsec_message.which_sub_message);
        if (vcsec_from_vcsec_message.which_sub_message == VCSEC_FromVCSECMessage_vehicleStatus_tag) {
            printf("User Present: %d\n", vcsec_from_vcsec_message.sub_message.vehicleStatus.userPresence);
            printf("Charging Port Open: %d\n",
                   vcsec_from_vcsec_message.sub_message.vehicleStatus.closureStatuses.chargePort);
        }

        return;
    }

    if (routable_message.has_signedMessageStatus) {
        TeslaBLE::Common::ErrorCodeToMessage(routable_message.signedMessageStatus.signed_message_fault);
        TeslaBLE::Common::OperationStatusToMessage(routable_message.signedMessageStatus.operation_status);
        return;
    }

    if (routable_message.which_payload == UniversalMessage_RoutableMessage_session_info_tag) {
        session.UpdateSessionInfo(routable_message.from_destination.sub_destination.
                                  domain,
                                  routable_message.payload.session_info.bytes,
                                  routable_message.payload.session_info.size);
    }
}

int main() {
    const char *vin = "XP7YGCEL0NB000000";
    unsigned char private_key[227] =
            "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEICrUkL0StUxZNhVRkK+QmeGDXVQvyjB6Iar8WQu3dDrloAoGCCqGSM49\nAwEHoUQDQgAEsvEtszFQqp8a83gIXsRBaS3UhOf6dgQDBoZWXSXIozABiawOfNF/\nOydB4e9zX5DiZYwTnUbWYlpqMk08cn4ZeA==\n-----END EC PRIVATE KEY-----";

    TeslaBLE::Authenticator authenticator = TeslaBLE::Authenticator{};
    authenticator.LoadPrivateKey(private_key, sizeof private_key);

    ble.registerMessageHandler(message_handler);
    int result = ble.connect((unsigned char *) vin);
    if (result != 0) {
        printf("Failed to connect to the vehicle.\n");
        return 1;
    }

    session.SetVIN((unsigned char *) vin);
    session.GenerateRoutingAddress();
    session.LoadAuthenticator(&authenticator);

    unsigned char sessionInfoRequestBuffer[200];
    size_t sessionInfoRequestBufferLength = 0;
    session.BuildRequestSessionInfoMessage(UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
                                           sessionInfoRequestBuffer, &sessionInfoRequestBufferLength);

    unsigned char securitySessionInfoRequestBuffer[200];
    size_t securitySessionInfoRequestBufferLength = 0;
    session.BuildRequestSessionInfoMessage(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
                                           securitySessionInfoRequestBuffer,
                                           &securitySessionInfoRequestBufferLength);


    //authenticator.CreatePrivateKey();
    //authenticator.BuildKeyWhitelistMessage(Keys_Role_ROLE_OWNER, sessionInfoRequestBuffer,
    //                                      &sessionInfoRequestBufferLength);

    int userInput;
    bool runLoop = true;
    bool hasUpdatedSessionInfo = false;

    // Prompt the user to enter a number
    std::cout << "\n\n1: Whitelist Private Key\n";
    std::cout << "2: Update SessionInfo\n";
    std::cout << "3: Climate ON\n";
    std::cout << "4: Climate OFF\n";
    std::cout << "5: Media Next Track\n";
    std::cout << "6: Lock\n";
    std::cout << "7: UnLock\n";
    std::cout << "8: Disconnect\n";
    std::cout << "9: Export VEHICLE_SECURITY SessionInfo\n";
    std::cout << "10: Export DOMAIN_INFOTAINMENT SessionInfo\n\n";

    while (runLoop) {
        std::cout << "Please select a command: ";
        std::cin >> userInput;

        size_t action_message_buffer_size = 0;
        unsigned char action_message_buffer[50];
        UniversalMessage_Domain domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;

        size_t session_size = 0;
        unsigned char session_buffer[Signatures_SessionInfo_size];

        size_t whitelist_size = 0;
        unsigned char whitelist_buffer[UniversalMessage_RoutableMessage_size];

        if (!hasUpdatedSessionInfo && userInput != 2 && userInput != 1) {
            std::cout << "\n\n\nYou have to execute command 2: to update the SessionInfo!\n\n\n";
        }

        std::cout << "\n";
        switch (userInput) {
            case 1:
                authenticator.BuildKeyWhitelistMessage(Keys_Role_ROLE_OWNER, whitelist_buffer, &whitelist_size);
                std::cout << "\n\n\nTouch NFC Card now!\n\n\n";
                break;
            case 2:
                ble.send((char *) sessionInfoRequestBuffer, sessionInfoRequestBufferLength);
                ble.send((char *) securitySessionInfoRequestBuffer, securitySessionInfoRequestBufferLength);
                hasUpdatedSessionInfo = true;
                std::cout << "SessionInfo updated\n";
                break;
            case 3:
                std::cout << "Sending climate on command\n";
                domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
                TeslaBLE::CarServer::TurnOnClimate(action_message_buffer, &action_message_buffer_size);
                break;
            case 4:
                std::cout << "Sending climate off command\n";
                domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
                TeslaBLE::CarServer::TurnOffClimate(action_message_buffer, &action_message_buffer_size);
                break;
            case 5:
                std::cout << "Sending media next track command\n";
                domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
                TeslaBLE::CarServer::NextMediaTrack(action_message_buffer, &action_message_buffer_size);
                break;
            case 6:
                std::cout << "Sending media next track command\n";
                domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
                TeslaBLE::Security::Lock(action_message_buffer, &action_message_buffer_size);
                break;
            case 7:
                std::cout << "Sending media next track command\n";
                domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
                TeslaBLE::Security::Unlock(action_message_buffer, &action_message_buffer_size);
                break;
            case 8:
                ble.close();
                runLoop = false;
                break;
            case 9:
                session.ExportSessionInfo(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, session_buffer,
                                          &session_size);
                TeslaBLE::Common::DumpHexBuffer("SessionInfo: ", session_buffer, session_size);
                break;
            case 10:
                session.ExportSessionInfo(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, session_buffer,
                                          &session_size);
                TeslaBLE::Common::DumpHexBuffer("SessionInfo: ", session_buffer, session_size);
                break;
            default:
                std::cout << "Please select a valid command.\n";
                break;
        }

        if (whitelist_size > 0) {
            ble.send((char *) whitelist_buffer, whitelist_size);
            whitelist_size = 0;
        }

        if (action_message_buffer_size > 0) {
            size_t output_message_buffer_size = 0;
            unsigned char output_message_buffer[UniversalMessage_RoutableMessage_size];

            session.BuildRoutableMessage(domain, action_message_buffer,
                                         action_message_buffer_size, output_message_buffer,
                                         &output_message_buffer_size);

            ble.send((char *) output_message_buffer, output_message_buffer_size);
            action_message_buffer_size = 0;
        }
    }

    return 0;
}
