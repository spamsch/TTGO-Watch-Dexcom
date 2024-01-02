/****************************************************************************
 *   Copyright  2023  Simon Pamies
 *   Email: spamsch@googlemail.com
 *
 *   @brief This module connects to a Dexcom G6 as a BLE client.
 *
 *   It is hooked into POWERMGM_STANDBY event and returns false so that
 *   the watch is prevented from going into light sleep. This is needed because
 *   the light sleep disables Wifi and BLE.
 *
 *   It will first scan for devices and then connect to a Dexcom device with
 *   a specific advertised UUID and a name that starts with Dexcom.
 * 
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "config.h"
#include "dexcomg6.h"

#include "../powermgm.h"
#include "../callback.h"
#include "mbedtls/aes.h"
#include "rom/crc.h"

#ifndef NATIVE_64BIT
#if defined(M5PAPER)
#elif defined(M5CORE2)
#elif defined(LILYGO_WATCH_2020_V1) || defined(LILYGO_WATCH_2020_V2) || defined(LILYGO_WATCH_2020_V3)
#include <TTGO.h>
#include "NimBLEDevice.h"
#include "NimBLEScan.h"
#elif defined(LILYGO_WATCH_2021)
#elif defined(WT32_SC01)
#else
#warning "Bluetooth is not supported on this device"
#endif
#endif

// General services that provide glucose values and e.g. battery information
static NimBLEUUID glucoseValuesServiceUUID("f8083532-849e-531c-c594-30f1f86a4ea5");
static NimBLEUUID deviceInformationServiceUUID("180A"); // The default service for the general device informations.
static NimBLEUUID advertisingServiceUUID("0000febc-0000-1000-8000-00805f9b34fb");

// The characteristic of the remote glucoseValueServiceUUID service we are interested in.
static NimBLEUUID communicationCharacteristicUUID("F8083533-849E-531C-C594-30F1F86A4EA5");  // NOTIFY, READ
static NimBLEUUID controlCharacteristicUUID("F8083534-849E-531C-C594-30F1F86A4EA5");        // INDICATE, WRITE
static NimBLEUUID authenticationCharacteristicUUID("F8083535-849E-531C-C594-30F1F86A4EA5"); // INDICATE, READ, WRITE (G6 Plus INDICATE / WRITE)
static NimBLEUUID backfillCharacteristicUUID("F8083536-849E-531C-C594-30F1F86A4EA5");       // NOTIFY, READ, WRITE (G6 Plus NOTIFY)

//  The general characteristic of the device information service such as the model name
static NimBLEUUID manufacturerCharacteristicUUID("2A29"); // READ
static NimBLEUUID modelCharacteristicUUID("2A24");        // READ
static NimBLEUUID firmwareCharacteristicUUID("2A26");     // READ

// Advertised device being a Dexcom
static NimBLEAdvertisedDevice *dexcomAdvertised = NULL;
static NimBLEClient *pClient = NULL;

// Characteristics that provide access to the glucose information
static NimBLERemoteCharacteristic *pRemoteCommunication;
static NimBLERemoteCharacteristic *pRemoteControl;
static NimBLERemoteCharacteristic *pRemoteAuthentication;
static NimBLERemoteCharacteristic *pRemoteBackfill;

static NimBLERemoteCharacteristic *pRemoteManufacturer;
static NimBLERemoteCharacteristic *pRemoteModel;
static NimBLERemoteCharacteristic *pRemoteFirmware;

// The identifier that can be found on the transmitter and also in the Dexcom app
static std::string transmitterIdentifier = "8QL745";

// Byte values for the notification / indication.
const uint8_t bothOff[] = {0x0, 0x0};
const uint8_t notificationOn[] = {0x1, 0x0};
const uint8_t indicationOn[] = {0x2, 0x0};
const uint8_t bothOn[] = {0x3, 0x0};

// Application state such as connection and bonding.
// Declared volatile as these will be changed by tasks.
static volatile boolean connected = false;
static volatile boolean bondingCanProceed = false;
static volatile boolean forceRebonding = false;
static volatile boolean bondingCompleted = false;

static std::string backfillStream = "";
static std::string AuthCallbackResponse = "";
static std::string ControlCallbackResponse = "";
static int backfillExpectedSequence = 1;
uint32_t transmitterStartTime = 0;

// Variables which survives the deep sleep. Uses RTC_SLOW memory.
#define saveLastXValues 12                                          // This saves the last x glucose levels by requesting them through the backfill request.
RTC_SLOW_ATTR static uint16_t glucoseValues[saveLastXValues] = {0}; // Reserve space for 1 hour a 5 min resolution of glucose values.

/**
 * CALLBACKS
 */

/**
 * @brief Callback that gets notified whenever the connection state changes
 * 
 * Will be set up as a callback before NimBLEDevice::createClient gets called. It
 * will set a global status variable `connected` to the state of the connection.
 * 
 */
class DexcomClientCallback : public NimBLEClientCallbacks
{

    void onDisconnect(NimBLEClient *pClient)
    {
        log_i("Dexcom BLE disconnected");
        connected = false;
    }

    void onConnect(NimBLEClient *pClient)
    {
        log_i("Dexcom BLE connected");
        connected = true;
    }
};

/**
 * @brief Will be set as the callback for bonding parameters.
 * 
 * This is important to ensure that any request to pair with security is
 * answered positively.
 * 
 */
class DexcomSecurityCallback : public NimBLESecurityCallbacks
{
    uint32_t onPassKeyRequest()
    {
        return 123456;
    }

    void onPassKeyNotify(uint32_t pass_key) {}

    bool onConfirmPIN(uint32_t pass_key)
    {
        return true;
    }

    bool onSecurityRequest()
    {
        return true;
    }

    void onAuthenticationComplete(ble_gap_conn_desc *auth_cmpl)
    {
        bondingCompleted = true;
    }
};

/**
 * @brief Callback that holds an executor that is called for each advertised device found
 * 
 */
class AllAdvertisedDeviceCallback : public NimBLEAdvertisedDeviceCallbacks
{
    void onResult(NimBLEAdvertisedDevice *advertisedDevice) // Called for each advertising BLE server.
    {
        if (advertisedDevice->haveServiceUUID() && advertisedDevice->isAdvertisingService(advertisingServiceUUID) && // If the advertised service is the dexcom advertise service (not the main service that contains the characteristics).
            advertisedDevice->haveName() && advertisedDevice->getName() == ("Dexcom" + transmitterIdentifier.substr(4, 2)))
        {
            log_i("Found Dexcom device. Stopping scan and trying to connect.");
            NimBLEDevice::getScan()->stop();
            // yields something like [I][dexcomg6.cpp:211] onResult(): Name: Dexcom45, Address: e1:4f:1c:93:9f:8b, manufacturer data: d000f103, serviceUUID: 0xfebc
            log_i("%s", advertisedDevice->toString().c_str());
            dexcomAdvertised = advertisedDevice;
            dexcomg6_initialize_connection();
        }
    }
};

/**
 * PRIVATE UTILITY FUNCTIONS
 */

/**
 * Calculate crc16 check sum for the given string.
 */
std::string CRC_16_XMODEM(std::string message)
{
    uint16_t crc = ~crc16_be((uint16_t)~0x0000, reinterpret_cast<const uint8_t *>(&message[0]), message.length()); // calculate crc 16 xmodem
    std::string crcString = {static_cast<char>((uint8_t)crc), static_cast<char>((uint8_t)(crc >> 8))};
    return crcString;
}

/**
 * Encrypt using AES 182 ecb (Electronic Code Book Mode).
 */
std::string dexcomg6_encrypt_aes(std::string buffer, std::string id)
{
    mbedtls_aes_context aes;

    std::string key = "00" + id + "00" + id; // The key (that also used the transmitter) for the encryption.
    unsigned char output[16];

    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, (const unsigned char *)key.c_str(), strlen(key.c_str()) * 8);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char *)buffer.c_str(), output);
    mbedtls_aes_free(&aes);

    std::string returnVal = "";
    for (int i = 0; i < 16; i++) // Convert unsigned char array to string.
    {
        returnVal += output[i];
    }
    return returnVal;
}

/**
 * Calculates the Hash for the given data.
 */
std::string dexcomg6_calculate_hash(std::string data, std::string id)
{
    data = data + data; // Use double the data to get 16 byte
    std::string hash = dexcomg6_encrypt_aes(data, id);
    return hash.substr(0, 8); // Only use the first 8 byte of the hash (ciphertext)
}

/**
 * Prints an uint8_t array as hex values.
 */
void dexcomg6_print_hex_array(uint8_t *data, size_t length)
{
    ESP_LOG_BUFFER_HEX_LEVEL("DXC", data, length, ESP_LOG_DEBUG);
}

/**
 * Converts an uint8_t array to string.
 */
std::string dexcomg6_uint8ToString(uint8_t *data, size_t length)
{
    std::string value = "";
    for (size_t i = 0; i < length; i++)
    {
        value += (char)data[i];
    }
    return value;
}

/**
 * The different callbacks for notify and indicate if new data from the transmitter is available.
 */
static void notifyCommunicationCallback(NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify)
{
    log_d("notifyCommunicationCallback - read %d byte data: ", length);
    dexcomg6_print_hex_array(pData, length);
}

static void indicateControlCallback(NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify)
{
    log_d("indicateControlCallback - read %d byte data: ", length);
    dexcomg6_print_hex_array(pData, length);
    ControlCallbackResponse = dexcomg6_uint8ToString(pData, length);
}

static void indicateAuthCallback(NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify)
{
    log_d("indicateAuthCallback - read %d byte data: ", length);
    dexcomg6_print_hex_array(pData, length);
    AuthCallbackResponse = dexcomg6_uint8ToString(pData, length);
}

static void notifyBackfillCallback(NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify)
{
    if (!dexcomg6_save_backfill(dexcomg6_uint8ToString(pData, length)))
    {
        log_e("Can't parse this backfill data: ");
        dexcomg6_print_hex_array(pData, length);
    }
}

/**
 * Wrapper function to send data to the authentication characteristic.
 */
/**
 * Write a string to the given characteristic.
 */
bool dexcomg6_write_value_to_characteristic(std::string caller, BLERemoteCharacteristic *pRemoteCharacteristic, std::string data)
{
    log_i("Caller %s", caller.c_str());
    uint8_t *pdata = reinterpret_cast<uint8_t *>(&data[0]); // convert std::string to uint8_t pointer
    /* important must be true so we don't flood the transmitter */
    pRemoteCharacteristic->writeValue(pdata, data.length(), true); // true = wait for response (acknowledgment) from the transmitter.
    return true;
}

/**
 * Register for notification, also check if notification is available.
 */
bool dexcomg6_register_for_service_notification(notify_callback _callback, BLERemoteCharacteristic *pBLERemoteCharacteristic)
{
    if (pBLERemoteCharacteristic->canNotify()) // Check if the characteristic has the potential to notify.
    {
        pBLERemoteCharacteristic->subscribe(true, _callback, false);
        log_i(" - Registered for notify on UUID: %s", pBLERemoteCharacteristic->getUUID().toString().c_str());
        return true;
    }
    else
    {
        log_i(" - Notify NOT available for UUID: %s", pBLERemoteCharacteristic->getUUID().toString().c_str());
    }
    return false;
}

bool dexcomg6_auth_send_value(std::string value)
{
    log_d("Auth send value %s", value);
    AuthCallbackResponse = ""; // Reset to invalid because we will write to the characteristic and must wait until new data arrived from the notify callback.
    return dexcomg6_write_value_to_characteristic("AuthSendValue", pRemoteAuthentication, value);
}

/**
 * Wrapper function to send data to the control characteristic.
 */
bool dexcomg6_control_send_value(std::string value)
{
    ControlCallbackResponse = "";
    return dexcomg6_write_value_to_characteristic("ControlSendValue", pRemoteControl, value);
}

/**
 * Barrier to wait until new data arrived through the notify callback.
 */
std::string dexcomg6_auth_wait_to_receive_cb()
{
    while (connected) // Only loop until we lost connection.
    {
        if (AuthCallbackResponse != "")
        {
            std::string returnValue = AuthCallbackResponse; // Save the new value.
            AuthCallbackResponse = "";                      // Reset because we handled the new data.
            return returnValue;
        }
    }
    return "";
}

/**
 * Barrier to wait until new data arrived through the notify callback.
 */
std::string dexcomg6_control_wait_to_receive_cb()
{
    while (connected) // Only loop until we lost connection.
    {
        if (ControlCallbackResponse != "")
        {
            std::string returnValue = ControlCallbackResponse; // Save the new value.
            ControlCallbackResponse = "";                      // Reset because we handled the new data.
            return returnValue;
        }
    }
    return "";
}

/**
 * For a given UUID retrieve the characteristic from the remote service and store it as a reference
 */
bool get_characteristic(NimBLERemoteCharacteristic **pRemoteCharacteristic, NimBLERemoteService *pRemoteService, BLEUUID uuid) // Use *pRemoteCharacteristic as an out parameter so get address/pointer of this pointer.
{
    *pRemoteCharacteristic = pRemoteService->getCharacteristic(uuid); // Write to where the pointer points (the pRemoteCharacteristic pointer address).
    if (*pRemoteCharacteristic == nullptr)
    {
        return false;
    }
    return true;
}

/**
 * This function will authenticate with the transmitter using a handshake and the transmitter identifier.
 * Return true if we are authenticated.
 */
bool dexcomg6_authenticate(bool useAlternativeChannel, std::string transmitterIdentifierProvided)
{
    log_i("Starting to authenticate against Dexcom device. Channel %i Transmitter %s", useAlternativeChannel, transmitterIdentifierProvided);
    std::string authRequestTxMessage = {0x01, 0x19, static_cast<char>(0xF3), static_cast<char>(0x89), static_cast<char>(0xF8), static_cast<char>(0xB7), 0x58, 0x41, 0x33}; // 0x02                 // 10byte, first byte = opcode (fix), [1] - [8] random bytes as challenge for the transmitter to encrypt,
    authRequestTxMessage += useAlternativeChannel ? 0x01 : 0x02;                                                                                                           // last byte 0x02 = normal bt channel, 0x01 alternative bt channel
    dexcomg6_auth_send_value(authRequestTxMessage);

    // Recv AuthChallengeRXMessage
    std::string authChallengeRxMessage = dexcomg6_auth_wait_to_receive_cb(); // Wait until we received data from the notify callback.
    if ((authChallengeRxMessage.length() != 17) || (authChallengeRxMessage[0] != 0x03))
    {
        log_e("Error wrong length or opcode from Dexcom authentication! %s", authChallengeRxMessage.c_str());
        return false;
    }
    std::string tokenHash = "";
    std::string challenge = "";
    for (int i = 1; i < authChallengeRxMessage.length(); i++) // Start with 1 to skip opcode.
    {
        if (i < 9)
            tokenHash += authChallengeRxMessage[i];
        else
            challenge += authChallengeRxMessage[i];
    }
    // Here we could check if the tokenHash is the encrypted 8 bytes from the authRequestTxMessage ([1] to [8]);
    // To check if the Transmitter is a valid dexcom transmitter (because only the correct one should know the ID).

    // Send AuthChallengeTXMessage
    std::string hash = dexcomg6_calculate_hash(challenge, transmitterIdentifierProvided); // Calculate the hash from the random 8 bytes the transmitter send us as a challenge.
    std::string authChallengeTXMessage = {0x04};                                          // opcode
    authChallengeTXMessage += hash;                                                       // in total 9 byte.
    dexcomg6_auth_send_value(authChallengeTXMessage);

    // Recv AuthStatusRXMessage
    std::string authStatusRXMessage = dexcomg6_auth_wait_to_receive_cb(); // Response { 0x05, 0x01 = authenticated / 0x02 = not authenticated, 0x01 = no bonding, 0x02 bonding
    if (authStatusRXMessage.length() == 3 && authStatusRXMessage[1] == 1) // correct response is 0x05 0x01 0x02
    {
        log_i("Authenticated with Dexcom transmitter!");
        bondingCanProceed = authStatusRXMessage[2] != 0x01;
        return true;
    }
    else
        log_i("Authenticated with Dexcom transmitter FAILED!");
    return false;
}

/**
 * @brief Setup bonding parameters by making sure that encryption is correct
 * 
 * @return true in all cases
 */
bool dexcomg6_setup_bonding()
{
    NimBLEDevice::setSecurityAuth(true, true, true);
    NimBLEDevice::setSecurityCallbacks(new DexcomSecurityCallback());

    NimBLESecurity *pSecurity = new NimBLESecurity();
    pSecurity->setKeySize();
    pSecurity->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_ONLY);
    pSecurity->setCapability(ESP_IO_CAP_IO);
    pSecurity->setRespEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);

    return (true);
}

/**
 * We have successfully authorized and now want to bond.
 * First enable the BLE security bonding options and then indicate the transmitter that he can now initiate a bonding.
 * Return true if no error occurs.
 */
bool dexcomg6_request_bond()
{
    if (bondingCanProceed)
    {
        if (forceRebonding) // Enable bonding after successful auth and before sending bond request to transmitter.
            dexcomg6_setup_bonding();

        log_i("Sending bonding request to Dexcom transmitter");

        // Send KeepAliveTxMessage
        std::string keepAliveTxMessage = {0x06, 0x19}; // Opcode 2 byte = 0x06, 25 as hex (0x19)
        dexcomg6_auth_send_value(keepAliveTxMessage);

        // Send BondRequestTxMessage
        std::string bondRequestTxMessage = {0x07}; // Send bonding command.
        dexcomg6_auth_send_value(bondRequestTxMessage);

        // Wait for bonding to finish. Will be set by DexcomSecurityCallback::onAuthenticationComplete
        log_i("Waiting for bonding with transmitter");
        while (bondingCompleted == false)
            ; // Barrier waits until bonding has finished, IMPORTANT to set the bondingFinished variable to sig_atomic_t OR volatile
        log_i("Bonding with Dexcom finished.");
    }
    else
        log_i("Transmitter does not want to (re)bond so DONT send bond request (already bonded).");

    return true;
}

/**
 * Read the time information from the transmitter.
 */
bool dexcomg6_read_time_message()
{
    std::string transmitterTimeTxMessage = {0x24, static_cast<char>(0xE6), 0x64};
    dexcomg6_control_send_value(transmitterTimeTxMessage);
    std::string transmitterTimeRxMessage = dexcomg6_control_wait_to_receive_cb();
    if ((transmitterTimeRxMessage.length() != 16) || transmitterTimeRxMessage[0] != 0x25)
        return false;

    uint8_t status = (uint8_t)transmitterTimeRxMessage[1];
    uint32_t currentTime = (uint32_t)(transmitterTimeRxMessage[2] +
                                      transmitterTimeRxMessage[3] * 0x100 +
                                      transmitterTimeRxMessage[4] * 0x10000 +
                                      transmitterTimeRxMessage[5] * 0x1000000);
    uint32_t sessionStartTime = (uint32_t)(transmitterTimeRxMessage[6] +
                                           transmitterTimeRxMessage[7] * 0x100 +
                                           transmitterTimeRxMessage[8] * 0x10000 +
                                           transmitterTimeRxMessage[9] * 0x1000000);
    log_i("Time - Status:              %d\n", status);
    log_i("Time - since activation:    %d (%d days, %d hours)\n", currentTime, // Activation date is now() - currentTime * 1000
          currentTime / (60 * 60 * 24),                                        // Days round down
          (currentTime / (60 * 60)) % 24);                                     // Remaining hours
    log_i("Time - since session start: %d\n", sessionStartTime);               // Session start = Activation date + sessionStartTime * 1000

    if (status == 0x81)                     // readTimeMessage is first request where we get the status code
        log_e("\nWARNING - Low Battery\n"); // So show a message when low battery / expired.
    if (status == 0x83)
        log_e("\nWARNING - Transmitter Expired\n");
    transmitterStartTime = currentTime;
    return true;
}

/**
 * Read the Battery values.
 */
bool dexcomg6_read_battery_status()
{
    std::string batteryStatusTxMessage = {0x22, 0x20, 0x04};
    dexcomg6_control_send_value(batteryStatusTxMessage);
    std::string batteryStatusRxMessage = dexcomg6_control_wait_to_receive_cb();
    if (!(batteryStatusRxMessage.length() == 10 || batteryStatusRxMessage.length() == 12) ||
        batteryStatusRxMessage[0] != 0x23)
        return false;

    log_i("Battery - Status:      %d\n", (uint8_t)batteryStatusRxMessage[1]);
    log_i("Battery - Voltage A:   %d\n", (uint16_t)(batteryStatusRxMessage[2] + batteryStatusRxMessage[3] * 0x100));
    log_i("Battery - Voltage B:   %d\n", (uint16_t)(batteryStatusRxMessage[4] + batteryStatusRxMessage[5] * 0x100));
    if (batteryStatusRxMessage.length() == 12) // G5 or G6 Transmitter.
    {
        log_i("Battery - Resistance:  %d\n", (uint16_t)(batteryStatusRxMessage[6] + batteryStatusRxMessage[7] * 0x100));
        log_i("Battery - Runtime:     %d\n", (uint8_t)batteryStatusRxMessage[8]);
        log_i("Battery - Temperature: %d\n", (uint8_t)batteryStatusRxMessage[9]);
    }
    else if (batteryStatusRxMessage.length() == 10) // G6 Plus Transmitter.
    {
        log_i("Battery - Runtime:     %d\n", (uint8_t)batteryStatusRxMessage[6]);
        log_i("Battery - Temperature: %d\n", (uint8_t)batteryStatusRxMessage[7]);
    }
    return true;
}

/**
 * Reads the glucose values from the transmitter.
 */
bool dexcomg6_read_glucose()
{
    std::string glucoseTxMessageG5 = {0x30, 0x53, 0x36};                                                                                    // G5 = 0x30 the other 2 bytes are the CRC16 XMODEM value in twisted order
    std::string glucoseTxMessageG6 = {0x4e, 0x0a, static_cast<char>(0xa9)};                                                                 // G6 = 0x4e
    if (transmitterIdentifier[0] == 8 || (transmitterIdentifier[0] == 2 && transmitterIdentifier[1] == 2 && transmitterIdentifier[2] == 2)) // Check if G6 or one of the newest G6 plus (>2.18.2.88) see https://github.com/xdrip-js/xdrip-js/issues/87
        dexcomg6_control_send_value(glucoseTxMessageG6);
    else
        dexcomg6_control_send_value(glucoseTxMessageG5);

    std::string glucoseRxMessage = dexcomg6_control_wait_to_receive_cb();
    if (glucoseRxMessage.length() < 16 || glucoseRxMessage[0] != (transmitterIdentifier[0] != 8 ? 0x31 : 0x4f)) // Opcode depends on G5 / G6
        return false;

    /*uint8_t status = (uint8_t)glucoseRxMessage[1];
    uint32_t sequence = (uint32_t)(glucoseRxMessage[2] +
                                   glucoseRxMessage[3] * 0x100 +
                                   glucoseRxMessage[4] * 0x10000 +
                                   glucoseRxMessage[5] * 0x1000000);
    uint32_t timestamp = (uint32_t)(glucoseRxMessage[6] +
                                    glucoseRxMessage[7] * 0x100 +
                                    glucoseRxMessage[8] * 0x10000 +
                                    glucoseRxMessage[9] * 0x1000000);*/

    uint16_t glucoseBytes = (uint16_t)(glucoseRxMessage[10] +
                                       glucoseRxMessage[11] * 0x100);
    // boolean glucoseIsDisplayOnly = (glucoseBytes & 0xf000) > 0;
    uint16_t glucose = glucoseBytes & 0xfff;
    uint8_t state = (uint8_t)glucoseRxMessage[12];
    // int trend = (int)glucoseRxMessage[13];
    if (state != 0x06) // Not the ok state -> exit
    {
        log_e("\nERROR - Session Status / State NOT OK (%d)!\n", state);
        return false;
    }

    if (saveLastXValues > 0) // Array is big enouth for min one value.
    {
        for (int i = saveLastXValues - 1; i > 0; i--) // Shift all old values back to set the newest to position 0.
            glucoseValues[i] = glucoseValues[i - 1];
        glucoseValues[0] = glucose;
    }
    return true;
}

/**
 * Reads the Sensor values like filtered / unfiltered raw data from the transmitter.
 */
bool dexcomg6_read_sensor()
{
    std::string sensorTxMessage = {0x2e, static_cast<char>(0xac), static_cast<char>(0xc5)};
    dexcomg6_control_send_value(sensorTxMessage);
    std::string sensorRxMessage = dexcomg6_control_wait_to_receive_cb();
    if ((sensorRxMessage.length() != 16 && sensorRxMessage.length() != 8) || sensorRxMessage[0] != 0x2f)
        return false;

    /*uint8_t status = (uint8_t)sensorRxMessage[1];
    uint32_t timestamp = (uint32_t)(sensorRxMessage[2] +
                                    sensorRxMessage[3] * 0x100 +
                                    sensorRxMessage[4] * 0x10000 +
                                    sensorRxMessage[5] * 0x1000000);*/
    if (sensorRxMessage.length() > 8)
    {
        uint32_t unfiltered = (uint32_t)(sensorRxMessage[6] +
                                         sensorRxMessage[7] * 0x100 +
                                         sensorRxMessage[8] * 0x10000 +
                                         sensorRxMessage[9] * 0x1000000);
        uint32_t filtered = (uint32_t)(sensorRxMessage[10] +
                                       sensorRxMessage[11] * 0x100 +
                                       sensorRxMessage[12] * 0x10000 +
                                       sensorRxMessage[13] * 0x1000000);
        if (transmitterIdentifier[0] == 8) // G6 Transmitter
        {
            int g6Scale = 34;
            unfiltered *= g6Scale;
            filtered *= g6Scale;
        }
    }

    return true;
}

/**
 * Reads out the last glucose calibration value.
 */
bool dexcomg6_read_last_calibration()
{
    std::string calibrationDataTxMessage = {0x32, 0x11, 0x16};
    dexcomg6_control_send_value(calibrationDataTxMessage);
    std::string calibrationDataRxMessage = dexcomg6_control_wait_to_receive_cb();
    if ((calibrationDataRxMessage.length() != 19 && calibrationDataRxMessage.length() != 20) ||
        (calibrationDataRxMessage[0] != 0x33))
        return false;

    /*uint16_t glucose = (uint16_t)(calibrationDataRxMessage[11] + calibrationDataRxMessage[12] * 0x100);
    uint32_t timestamp = (uint32_t)(calibrationDataRxMessage[13] +
                                    calibrationDataRxMessage[14] * 0x100 +
                                    calibrationDataRxMessage[15] * 0x10000 +
                                    calibrationDataRxMessage[16] * 0x1000000);*/

    return true;
}

/**
 * Reads the last glucose values from the transmitter when the esp was not connected.
 */
bool dexcomg6_read_backfill()
{
    if (transmitterStartTime == 0) // The read time command must be send first to get the current time.
        return false;

    backfillStream = "";          // Empty the backfill stream.
    backfillExpectedSequence = 1; // Set to the first message.

    std::string backfillTxMessage = {0x50, 0x05, 0x02, 0x00}; // 18 + 2 byte crc = 20 byte
    // Set backfill_start to 0 to get all values of the last ~150 measurements (~12,5h)
    uint32_t backfill_start = transmitterStartTime - (saveLastXValues * 5) * 60; // Get the last x values. Only need x-1 because we already have the current value but request one more to be sure that we get x-1.
    uint32_t backfill_end = transmitterStartTime - 60;                           // Do not request the current value. (But is not anyway available by backfill)

    backfillTxMessage += (uint8_t(backfill_start >> 0));
    backfillTxMessage += (uint8_t(backfill_start >> 8));
    backfillTxMessage += (uint8_t(backfill_start >> 16));
    backfillTxMessage += (uint8_t(backfill_start >> 24));

    backfillTxMessage += (uint8_t(backfill_end >> 0));
    backfillTxMessage += (uint8_t(backfill_end >> 8));
    backfillTxMessage += (uint8_t(backfill_end >> 16));
    backfillTxMessage += (uint8_t(backfill_end >> 24));

    backfillTxMessage += {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // Fill up to 18 byte.
    backfillTxMessage += CRC_16_XMODEM(backfillTxMessage);     // Add crc 16.

    dexcomg6_control_send_value(backfillTxMessage);
    std::string backfillRxMessage = dexcomg6_control_wait_to_receive_cb(); // We will receive this normally after all backfill data has been send by the transmitter.
    if (backfillRxMessage.length() != 20 || backfillRxMessage[0] != 0x51)
        return false;

    uint8_t status = (uint8_t)backfillRxMessage[1];
    uint8_t backFillStatus = (uint8_t)backfillRxMessage[2];
    uint8_t identifier = (uint8_t)backfillRxMessage[3];
    uint32_t timestampStart = (uint32_t)(backfillRxMessage[4] +
                                         backfillRxMessage[5] * 0x100 +
                                         backfillRxMessage[6] * 0x10000 +
                                         backfillRxMessage[7] * 0x1000000);
    uint32_t timestampEnd = (uint32_t)(backfillRxMessage[8] +
                                       backfillRxMessage[9] * 0x100 +
                                       backfillRxMessage[10] * 0x10000 +
                                       backfillRxMessage[11] * 0x1000000);
    log_i("Backfill - Status:          %d\n", status);
    log_i("Backfill - Backfill Status: %d\n", backFillStatus);
    log_i("Backfill - Identifier:      %d\n", identifier);
    log_i("Backfill - Timestamp Start: %d\n", timestampStart);
    log_i("Backfill - Timestamp End:   %d\n", timestampEnd);

    delay(2 * 1000); // Wait 2 seconds to be sure that all backfill data has arrived.
    return true;
}

/**
 * This method parsed 8 bytes representing the timestamp and glucose values.
 */
void dexcomg6_parse_backfill(std::string data)
{
    uint32_t dextime = (uint32_t)(data[0] +
                                  data[1] * 0x100 +
                                  data[2] * 0x10000 +
                                  data[3] * 0x1000000);
    uint16_t glucose = (uint16_t)(data[4] + data[5] * 0x100);
    uint8_t type = (uint8_t)data[6];
    // uint8_t trend = (uint8_t)data[7];

    if (saveLastXValues > 1) // Array is big enouth for min 1 backfill value (and the current value).
    {
        for (int i = saveLastXValues - 1; i > 1; i--) // Shift all old values (but not the first) back to save these.
            glucoseValues[i] = glucoseValues[i - 1];
        glucoseValues[1] = glucose;
    }

    log_i("Backfill -> Dextime: %d   Glucose: %d   Type: %d\n", dextime, glucose, type);
}

/**
 * This method saves the backfill data received from the backfill characteristic callback.
 */
bool dexcomg6_save_backfill(std::string backfillParseMessage)
{
    if (backfillParseMessage.length() < 2) // Minimum is sequence + identifier.
        return false;

    uint8_t sequence = (uint8_t)backfillParseMessage[0];
    // uint8_t identifier = (uint8_t)backfillParseMessage[1];

    if (sequence != backfillExpectedSequence)
    {
        backfillExpectedSequence = 0; // After one out of order package the other packages can't be used.
        return false;
    }
    backfillExpectedSequence += 1;

    if (sequence == 1)
    {
        // uint16_t backfillRequestCounter = (uint16_t)(backfillParseMessage[2] + backfillParseMessage[3] * 0x100);
        // uint16_t unknown = (uint16_t)(backfillParseMessage[4] + backfillParseMessage[5] * 0x100);
        backfillStream = backfillParseMessage.substr(6); // Empty string and set payload.
    }
    else
        backfillStream += backfillParseMessage.substr(2); // Add data.

    while (backfillStream.length() >= 8)
    {
        std::string data = backfillStream.substr(0, 8); // Get the first 8 byte.
        if (backfillStream.length() > 8)                // More than 8 byte?
            backfillStream = backfillStream.substr(8);  // Trim of the first 8 byte.
        else                                            // Exactly 8 byte:
            backfillStream = "";                        // Empty string.
        dexcomg6_parse_backfill(data);
    }
    return true;
}

/**
 * Sending command to initiate a disconnect from the transmitter.
 */
bool dexcomg6_send_disconnect()
{
    log_i("Initiating a disconnect");
    std::string disconnectTxMessage = {0x09};
    dexcomg6_control_send_value(disconnectTxMessage);
    while (connected)
        ; // Wait until onDisconnect callback was called and connected status flipped.
    return true;
}

/**
 * Register for indication AND notification, without checking.
 */
bool dexcomg6_force_register_for_service_notification_and_indication(notify_callback _callback, BLERemoteCharacteristic *pBLERemoteCharacteristic, bool isNotify)
{
    pBLERemoteCharacteristic->subscribe(isNotify, _callback, false);                                            // Register first for indication(/notification) (because this is the correct one)
    pBLERemoteCharacteristic->getDescriptor(BLEUUID((uint16_t)0x2902))->writeValue((uint8_t *)bothOn, 2, true); // True to wait for acknowledge, set to both, manually set the bytes because there is no such funktion to set both.
    log_d(" - FORCE registered for indicate and notify on UUID: %s", pBLERemoteCharacteristic->getUUID().toString().c_str());
    return true;
}

/**
 * Register for indication, also check if indications are available.
 */
bool dexcomg6_register_cb_for_indication(notify_callback _callback, BLERemoteCharacteristic *pBLERemoteCharacteristic)
{
    if (pBLERemoteCharacteristic->canIndicate())
    {
        pBLERemoteCharacteristic->subscribe(false, _callback, false); // false = indication, true = notification
        log_i(" - Registered for indicate on UUID: %s", pBLERemoteCharacteristic->getUUID().toString().c_str());
        return true;
    }
    else
    {
        log_i(" - Indicate NOT available for UUID: %s", pBLERemoteCharacteristic->getUUID().toString().c_str());
    }
    return false;
}

static bool dexcomg6_powermgm_event_cb(EventBits_t event, void *arg)
{
    log_i("Powermgmt called for Dexcom");
    switch( event ) {
        case POWERMGM_STANDBY:  log_i("Standby requested but denying to allow connection keep alive");
                                return false;
        case POWERMGM_WAKEUP:   log_i("Wakeup - checking if connection still active");
                                if (!connected) NimBLEDevice::getScan()->start(0, true);
                                return true;
    }
    return (true);
}

/**
 * @brief called by AllAdvertisedDeviceCallback->onResult when a Dexcom device has been found.
 *
 * Initializes the connection by connecting to services and then setting up characteristics.
 */
void dexcomg6_initialize_connection()
{
    if (dexcomAdvertised != NULL)
    {
        log_d("Setup bonding with encryption parameters");
        dexcomg6_setup_bonding();

        pClient = NimBLEDevice::createClient();
        pClient->setClientCallbacks(new DexcomClientCallback());
        log_d("Before connection to Dexcom as a client");
        connected = pClient->connect(dexcomAdvertised);

        if (connected)
        {
            log_i("Connection to Dexcom advertising service has been established");

            // A BLE server can provide multiple services that are identified by a UUID
            NimBLERemoteService *pGlucoseValueService = pClient->getService(glucoseValuesServiceUUID);
            if (pGlucoseValueService == nullptr)
            {
                pClient->disconnect();
                log_e("Could not find Glucose Value Service in Dexcom device");
            }
            else
            {
                log_i("Found Glucose Value Service, now looking for Device Information Service");
                NimBLERemoteService *pDeviceInfoService = pClient->getService(deviceInformationServiceUUID);
                if (pDeviceInfoService == nullptr)
                {
                    pClient->disconnect();
                    log_e("Could not find Device Information Service in Dexcom device");
                }
                else
                {
                    log_i("Setting up characteristics for Dexcom services");
                    get_characteristic(&pRemoteCommunication, pGlucoseValueService, communicationCharacteristicUUID);
                    get_characteristic(&pRemoteControl, pGlucoseValueService, controlCharacteristicUUID);
                    get_characteristic(&pRemoteAuthentication, pGlucoseValueService, authenticationCharacteristicUUID);
                    get_characteristic(&pRemoteBackfill, pGlucoseValueService, backfillCharacteristicUUID);

                    get_characteristic(&pRemoteManufacturer, pDeviceInfoService, manufacturerCharacteristicUUID);
                    get_characteristic(&pRemoteModel, pDeviceInfoService, modelCharacteristicUUID);
                    get_characteristic(&pRemoteFirmware, pDeviceInfoService, firmwareCharacteristicUUID);

                    log_d("Forcing registration of notifications for Dexcom authentication service");
                    dexcomg6_force_register_for_service_notification_and_indication(indicateAuthCallback, pRemoteAuthentication, false);

                    if (pRemoteManufacturer->canRead())
                    {
                        log_i("Found Dexcom manufacturer %s", pRemoteManufacturer->readValue().c_str());
                        log_i("Found Dexcom model name %s", pRemoteModel->readValue().c_str());
                        log_i("Found Dexcom firmware ident %s", pRemoteFirmware->readValue().c_str());
                        pClient->disconnect();
                        /*bool authenticatedOk = dexcomg6_authenticate(true, transmitterIdentifier);
                        if (authenticatedOk)
                        {
                            bool bonded = dexcomg6_request_bond();
                            if (bonded)
                            {
                                dexcomg6_force_register_for_service_notification_and_indication(indicateControlCallback, pRemoteControl, false);
                            }
                        }*/
                    }
                    else
                    {
                        pClient->disconnect();
                        log_e("Could not read Dexcom manufacturing information");
                    }
                }
            }
        }
        else {
            log_e("Could not connect to Dexcom device");
            pClient->disconnect();
        }
    }
}

void dexcomg6_initialize_scan_parameters()
{
    log_i("Initializing bluetooth scan parameters. Looking for dexcom advertising UUID %s", advertisingServiceUUID.toString().c_str());
    NimBLEDevice::init("TWatch2020v3");

    // this is a singleton and will always return the same scan class
    NimBLEScan *pBLEScan = NimBLEDevice::getScan();                            // Retrieve a Scanner.
    pBLEScan->setAdvertisedDeviceCallbacks(new AllAdvertisedDeviceCallback()); // Set the callback to informed when a new device was detected.
    pBLEScan->setInterval(100);                                                // 100 works                                                                             // The time in ms how long each search intervall last. Important for fast scanning so we dont miss the transmitter waking up.
    pBLEScan->setWindow(99);                                                   // 60-99 works                                                                              // The actual time that will be searched. Interval - Window = time the esp is doing nothing (used for energy efficiency).
    pBLEScan->setActiveScan(false);
}

void dexcomg6_setup(void)
{
    powermgm_register_cb(POWERMGM_STANDBY | POWERMGM_WAKEUP | POWERMGM_SILENCE_WAKEUP, dexcomg6_powermgm_event_cb, "dexcom g6 powermgmt event");
    dexcomg6_initialize_scan_parameters();

    /// start scan and upon finding devices call @see{AllAdvertisedCallback::onConnect} which will take care of handling the next steps
    log_i("Starting scanning of bluetooth devices. Dexcom is not advertising all the time so a connection might take a while");
    NimBLEDevice::getScan()->start(0, true);
}
