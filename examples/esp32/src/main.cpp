#include <session.h>
#include <shared.h>
#include <authenticator.h>
#include <hal/usb_serial_jtag_ll.h>
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <iostream>
#include <security.h>
#include <carserver.h>
#include "NimBLEDevice.h"
#include <mbedtls/gcm.h>

static NimBLEUUID serviceUUID("00000211-b2d1-43f0-9b88-960cebf8b91e");
static NimBLEUUID readUUID("00000213-b2d1-43f0-9b88-960cebf8b91e");
static NimBLEUUID writeUUID("00000212-b2d1-43f0-9b88-960cebf8b91e");

static NimBLERemoteCharacteristic *readCharacteristic;
static NimBLERemoteCharacteristic *writeCharacteristic;

TeslaBLE::Authenticator authenticator = TeslaBLE::Authenticator{};
TeslaBLE::Session session = TeslaBLE::Session{};

unsigned char ble_buffer[200];
size_t current_message_size = 0;

extern "C"
{
    void app_main(void);
}

void readInput(void *pvParameter)
{
    uint8_t rxbuf[1];

    printf("\n1: Climate ON\n2: Climate OFF\n3: Media Next Track\n4: Lock\n5: UnLock\n\nPlease select a command: ");
    size_t action_message_buffer_size = 0;
    unsigned char action_message_buffer[50];
    UniversalMessage_Domain domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;

    size_t output_message_buffer_size = 0;
    unsigned char output_message_buffer[UniversalMessage_RoutableMessage_size];

    while (1)
    {
        if (usb_serial_jtag_ll_rxfifo_data_available())
        {
            usb_serial_jtag_ll_read_rxfifo(rxbuf, 1);

            switch (rxbuf[0])
            {
            case 49:
                printf("Sending climate on command\n");
                domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
                TeslaBLE::CarServer::TurnOnClimate(action_message_buffer, &action_message_buffer_size);
                break;
            case 50:
                printf("Sending climate off command\n");
                domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
                TeslaBLE::CarServer::TurnOffClimate(action_message_buffer, &action_message_buffer_size);
                break;
            case 51:
                printf("Sending media next track command\n");
                domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
                TeslaBLE::CarServer::NextMediaTrack(action_message_buffer, &action_message_buffer_size);
                break;
            case 52:
                printf("Sending lock command\n");
                domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
                TeslaBLE::Security::Lock(action_message_buffer, &action_message_buffer_size);
                break;
            case 53:
                printf("Sending unlock command\n");
                domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
                TeslaBLE::Security::Unlock(action_message_buffer, &action_message_buffer_size);
                break;
            default:
                action_message_buffer_size = 0;
                printf("Please select a valid command.\n");
                break;
            }

            if (action_message_buffer_size > 0)
            {
                session.BuildRoutableMessage(domain, action_message_buffer,
                                             action_message_buffer_size, output_message_buffer,
                                             &output_message_buffer_size);

                writeCharacteristic->writeValue(output_message_buffer, output_message_buffer_size);

                action_message_buffer_size = 0;
                output_message_buffer_size = 0;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    free(rxbuf);
    vTaskDelete(NULL);
}

void handleMessage() {
        TeslaBLE::Common::DumpHexBuffer("RX: ", ble_buffer, current_message_size);

        UniversalMessage_RoutableMessage routable_message = UniversalMessage_RoutableMessage_init_zero;
        TeslaBLE::Common::DecodeRoutableMessage(ble_buffer, current_message_size, &routable_message);

        current_message_size = 0;

        if (routable_message.has_to_destination && routable_message.to_destination.sub_destination.
        domain == UniversalMessage_Domain_DOMAIN_BROADCAST) {
        // printf("Dropping broadcast message\n");

        VCSEC_FromVCSECMessage vcsec_from_vcsec_message = VCSEC_FromVCSECMessage_init_default;
        TeslaBLE::Common::DecodeFromVCSECMessage(routable_message.payload.protobuf_message_as_bytes.bytes,
                                                 routable_message.payload.protobuf_message_as_bytes.size,
                                                 &vcsec_from_vcsec_message);

        printf("Sub Message: %d\n", vcsec_from_vcsec_message.which_sub_message);
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

void notifyCB(NimBLERemoteCharacteristic *pRemoteCharacteristic, uint8_t *pData,
              size_t length, bool isNotify)
{
    unsigned char input_buffer[length];
    memcpy(&input_buffer, pData, length);
    const size_t size = TeslaBLE::Common::ExtractLength(input_buffer);

    if (current_message_size == 0 && size > length) {
            current_message_size = 0;

            size_t payload_size = length - 2;
            memcpy(ble_buffer, input_buffer + 2, payload_size);
            current_message_size = payload_size;
            return;
        }

        if (current_message_size > 0) {
            memcpy(ble_buffer + current_message_size, input_buffer, length);
            current_message_size = current_message_size + length;
            handleMessage();
            return;
        }

        size_t payload_size = length - 2;
        memcpy(ble_buffer, input_buffer + 2, payload_size);
        current_message_size = payload_size;
        handleMessage();
}

bool connectToCar()
{
        printf("Connect to car!\n");

    BLEClient *pClient = BLEDevice::createClient();
    pClient->connect(NimBLEAddress("b0:d2:78:87:26:72"));

    if (!pClient->isConnected())
    {
        printf("Failed to connect!\n");
        return false;
    }

    printf("Connected to car!\n");

    BLERemoteService *pRemoteService = pClient->getService(serviceUUID);
    if (pRemoteService == nullptr)
    {
        printf("Failed to find our service UUID: %s\n",
               serviceUUID.toString().c_str());
        pClient->disconnect();
        return false;
    }

    readCharacteristic = pRemoteService->getCharacteristic(readUUID);
    if (readCharacteristic == nullptr)
    {
        printf("Failed to find our read characteristic UUID: %s\n",
               readUUID.toString().c_str());
        pClient->disconnect();
        return false;
    }

    if (!readCharacteristic->subscribe(false, notifyCB))
    {
        printf("Failed to subscribe to characteristic UUID: %s\n",
                 readUUID.toString().c_str());
        return false;
    }

    writeCharacteristic = pRemoteService->getCharacteristic(writeUUID);
    if (writeCharacteristic == nullptr)
    {
        printf("Failed to find our write characteristic UUID: %s\n",
               writeUUID.toString().c_str());
        pClient->disconnect();
        return false;
    }

    return true;
}

void connectTask(void *parameter)
{
     if (connectToCar())
    {
        printf("We are now connected to the Car.\n");

        unsigned char sessionInfoRequestBuffer[200];
        size_t sessionInfoRequestBufferLength = 0;
        session.BuildRequestSessionInfoMessage(UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
                                                    sessionInfoRequestBuffer, &sessionInfoRequestBufferLength);
        writeCharacteristic->writeValue(sessionInfoRequestBuffer, sessionInfoRequestBufferLength);

        session.BuildRequestSessionInfoMessage(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
                                                    sessionInfoRequestBuffer, &sessionInfoRequestBufferLength);
        writeCharacteristic->writeValue(sessionInfoRequestBuffer, sessionInfoRequestBufferLength);

        xTaskCreate(readInput, "readInput", 10000, NULL, 1, NULL);
    }
    else
    {
        printf("We have failed to connect to the server; there is nothin more we will do.\n");
    }

    vTaskDelete(NULL);
}

void app_main()
{
    NimBLEDevice::init("TeslaBLE");
    
    const char *vin = "XP7YGCEL0NB000000";
    unsigned char private_key[227] =
            "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEICrUkL0StUxZNhVRkK+QmeGDXVQvyjB6Iar8WQu3dDrloAoGCCqGSM49\nAwEHoUQDQgAEsvEtszFQqp8a83gIXsRBaS3UhOf6dgQDBoZWXSXIozABiawOfNF/\nOydB4e9zX5DiZYwTnUbWYlpqMk08cn4ZeA==\n-----END EC PRIVATE KEY-----";

    authenticator.LoadPrivateKey(private_key, sizeof private_key);

    session.SetVIN((unsigned char*)vin);
    session.GenerateRoutingAddress();
    session.LoadAuthenticator(&authenticator);

    xTaskCreate(connectTask, "connectTask", 5000, NULL, 1, NULL);
}