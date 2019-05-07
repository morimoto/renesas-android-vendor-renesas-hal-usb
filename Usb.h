#ifndef ANDROID_HARDWARE_USB_V1_0_USB_H
#define ANDROID_HARDWARE_USB_V1_0_USB_H

#include <android/hardware/usb/1.0/IUsb.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <log/log.h>

#include <map>

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "android.hardware.usb@1.0-service.renesas"
#define UEVENT_MSG_LEN 2048

namespace android {
namespace hardware {
namespace usb {
namespace V1_0 {
namespace implementation {


using ::android::hardware::usb::V1_0::IUsbCallback;
using ::android::hardware::usb::V1_0::PortRole;
using ::android::hidl::base::V1_0::IBase;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct UsbPortEntry
{
    std::string name;
    std::string id;
    PortMode mode;

    bool canChangeMode;
    bool canChangeDataRole;
    bool canChangePowerRole;
};

struct UsbPortConfig
{
    Status readConfigFromXML();

    bool isConfigRead;
    std::map<std::string, UsbPortEntry> availablePorts;

private:
    PortMode modeFromConfigString(const char* modeName);
    bool isModeSwitchDenied(const char* xmlProp);
    bool validatePort(const UsbPortEntry& portEntry);
};

struct Usb : public IUsb
{
    Usb();

    Return<void> switchRole(const hidl_string& portName, const PortRole& role) override;
    Return<void> setCallback(const sp<IUsbCallback>& callback) override;
    Return<void> queryPortStatus() override;

    sp<IUsbCallback> mCallback;

private:
    // helpers
    Status getPortStatusVec(hidl_vec<PortStatus>& currentPortStatus);

    Status getSinglePortStatus(const UsbPortEntry& port, PortStatus& status);

    pthread_t mPoll;
    pthread_mutex_t mLock = PTHREAD_MUTEX_INITIALIZER;

    UsbPortConfig mUsbConfig;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace usb
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_USB_V1_0_USB_H
