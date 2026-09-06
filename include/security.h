/*
* TeslaBLE © 2024 by Pascal Matthiesen
 */

#ifndef TESLA_BLE_SECURITY_H
#define TESLA_BLE_SECURITY_H

#include <vcsec.pb.h>

namespace TeslaBLE {
    class Security {
        static int BuildUnsignedMessage(const VCSEC_UnsignedMessage *unsigned_message, unsigned char *buffer,
                                        size_t *buffer_size);

        static int BuildRkeAction(VCSEC_RKEAction_E action, unsigned char *buffer, size_t *buffer_size);

        static int BuildClosureMove(VCSEC_ClosureMoveType_E rear_trunk, VCSEC_ClosureMoveType_E front_trunk,
                                    VCSEC_ClosureMoveType_E tonneau, unsigned char *buffer, size_t *buffer_size);

    public:
        static int Unlock(unsigned char *buffer, size_t *buffer_size);

        static int Lock(unsigned char *buffer, size_t *buffer_size);

        static int Wake(unsigned char *buffer, size_t *buffer_size);

        static int AutoSecure(unsigned char *buffer, size_t *buffer_size);

        static int RemoteDrive(unsigned char *buffer, size_t *buffer_size);

        static int OpenTrunk(unsigned char *buffer, size_t *buffer_size);

        static int CloseTrunk(unsigned char *buffer, size_t *buffer_size);

        static int OpenFrunk(unsigned char *buffer, size_t *buffer_size);

        static int OpenTonneau(unsigned char *buffer, size_t *buffer_size);

        static int CloseTonneau(unsigned char *buffer, size_t *buffer_size);

        static int StopTonneau(unsigned char *buffer, size_t *buffer_size);

        static int GetStatus(unsigned char *buffer, size_t *buffer_size);
    };
} // TeslaBLE

#endif //TESLA_BLE_SECURITY_H
