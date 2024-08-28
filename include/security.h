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

    public:
        static int Unlock(unsigned char *buffer, size_t *buffer_size);

        static int Lock(unsigned char *buffer, size_t *buffer_size);

        static int Wake(unsigned char *buffer, size_t *buffer_size);
    };
} // TeslaBLE

#endif //TESLA_BLE_SECURITY_H
