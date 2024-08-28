/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#ifndef TESLA_BLE_CARSERVER_H
#define TESLA_BLE_CARSERVER_H
#include <car_server.pb.h>
#include <shared.h>

namespace TeslaBLE {
    class CarServer {
        static int BuildActionMessage(
            CarServer_Action *car_server_action, unsigned char *buffer, size_t *buffer_size);

        static int ToggleClimate(bool status, unsigned char *buffer, size_t *buffer_size);

    public:
        static int TurnOnClimate(unsigned char *buffer, size_t *buffer_size);

        static int TurnOffClimate(unsigned char *buffer, size_t *buffer_size);

        static int NextMediaTrack(unsigned char *buffer, size_t *buffer_size);

        static int PlayMedia(unsigned char *buffer, size_t *buffer_size);

        static int SetVolume(float absolute, unsigned char *buffer, size_t *buffer_size);

        static int SetChargingLimit(int32_t percent, unsigned char *buffer, size_t *buffer_size);

        static int Vent(unsigned char *buffer, size_t *buffer_size);

        static int StartCharging(unsigned char *buffer, size_t *buffer_size);

        static int StopCharging(unsigned char *buffer, size_t *buffer_size);

        static int OpenChargePort(unsigned char *buffer, size_t *buffer_size);

        static int CloseChargePort(unsigned char *buffer, size_t *buffer_size);
    };
} // TeslaBLE

#endif //TESLA_BLE_CARSERVER_H
