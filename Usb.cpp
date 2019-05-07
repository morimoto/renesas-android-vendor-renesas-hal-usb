/*
 * Copyright (C) 2018 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0

#include <iostream>
#include <fstream>
#include <string>

#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <cutils/uevent.h>
#include <sys/epoll.h>
#include <utils/Errors.h>
#include <utils/StrongPointer.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "Usb.h"

#define SYS_USB_PATH "/sys/devices/platform/soc/"

namespace android {
namespace hardware {
namespace usb {
namespace V1_0 {
namespace implementation {

PortMode UsbPortConfig::modeFromConfigString(const char* modeName)
{
    if(!strcmp(modeName, "host")) {
        return PortMode::DFP;
    } else if(!strcmp(modeName, "device")) {
        return PortMode::UFP;
    } else if(!strcmp(modeName, "dual")) {
        return PortMode::DRP;
    }

    return PortMode::NONE;
}

bool UsbPortConfig::isModeSwitchDenied(const char* xmlProp)
{
    if(xmlProp) {
        if(!strcmp(xmlProp, "true")) {
            return true;
        } else if(!strcmp(xmlProp, "false")) {
            return false;
        }
    }

    return false;
}

Status UsbPortConfig::readConfigFromXML()
{
    const char* xmlPath = "/vendor/etc/usb_port_configuration.xml";

    ALOGV("reading config");

    isConfigRead = false;

    xmlDoc* xmlConfigDoc = xmlReadFile(xmlPath, NULL, 0);
    if (xmlConfigDoc == NULL) {
        ALOGE("readConfigFromXML: port config not found at \"%s\n\"", xmlPath);
        return Status::ERROR;
    }

    xmlNode* rootElement = xmlDocGetRootElement(xmlConfigDoc);

    // read all <port> node parameters under <usbports>
    for (xmlNode* currentNode = rootElement->children; currentNode;
         currentNode = currentNode->next) {
        if (currentNode->type == XML_ELEMENT_NODE) {
            UsbPortEntry newPortEntry;

            newPortEntry.name = (char *) xmlGetProp(currentNode, (const xmlChar *) "name");
            newPortEntry.id = (char *) xmlGetProp(currentNode, (const xmlChar *) "id");
            newPortEntry.mode = modeFromConfigString(
                (char *) xmlGetProp(currentNode, (const xmlChar *) "mode"));

            bool modeSwitchDenied = isModeSwitchDenied(
                (char *) xmlGetProp(currentNode, (const xmlChar *) "noswitch"));

            if(!modeSwitchDenied && newPortEntry.mode == PortMode::DRP) {
                newPortEntry.canChangeDataRole = true;
                newPortEntry.canChangePowerRole = true;
                newPortEntry.canChangeMode = true;
            } else {
                newPortEntry.canChangeDataRole = false;
                newPortEntry.canChangePowerRole = false;
                newPortEntry.canChangeMode = false;
            }

            if(validatePort(newPortEntry)) {
                availablePorts[newPortEntry.name] = newPortEntry;
            }
        }
    }

    xmlFreeDoc(xmlConfigDoc);
    xmlCleanupParser();
    isConfigRead = true;

    void checkForAvailablePorts();

    return Status::SUCCESS;
}

bool UsbPortConfig::validatePort(const UsbPortEntry& portEntry)
{
    std::string portPath = SYS_USB_PATH + portEntry.id;

    DIR *dp = opendir(portPath.c_str());
    if (!dp) {
        ALOGE("failed to open %s", portPath.c_str());
        return false;
    }

    // path exists, that's enough for now
    return true;
}

// helpers
Status readFile(std::string filename, std::string& contents)
{
    std::ifstream file(filename);

    if (!file.is_open()) {
        return Status::ERROR;
    }

    getline(file, contents);
    return Status::SUCCESS;
}

Status writeFile(std::string filename, std::string contents)
{
    std::ofstream file(filename);

    if (!file.is_open()) {
        return Status::ERROR;
    }

    file << contents;
    return Status::SUCCESS;
}

std::string convertToRoleString(PortRole role)
{
    if (role.type == PortRoleType::POWER_ROLE) {
        if (role.role == static_cast<uint32_t> (PortPowerRole::SOURCE))
            return "host";
        else if (role.role ==  static_cast<uint32_t> (PortPowerRole::SINK))
            return "peripheral";
    } else if (role.type == PortRoleType::DATA_ROLE) {
        if (role.role == static_cast<uint32_t> (PortDataRole::HOST))
            return "host";
        if (role.role == static_cast<uint32_t> (PortDataRole::DEVICE))
            return "peripheral";
    } else if (role.type == PortRoleType::MODE) {
        if (role.role == static_cast<uint32_t> (PortMode::UFP))
            return "peripheral";
        if (role.role == static_cast<uint32_t> (PortMode::DFP))
            return "host";
    }
    return std::string();
}

Status Usb::getSinglePortStatus(const UsbPortEntry& port, PortStatus& status)
{
    ALOGV("querying port %s", port.name.c_str());

    // TODO: add code path for devices with pure UFP ports
    if(port.mode == PortMode::DFP)
    {
        // skip any checks, such port doesn't change
        status.currentPowerRole = PortPowerRole::SOURCE;
        status.currentDataRole = PortDataRole::HOST;
        status.currentMode = PortMode::DFP;
    } else {
        // do actual query
        std::string portModeFilesystemPath = SYS_USB_PATH + port.id + "/role";
        std::string readValue;

        if(readFile(portModeFilesystemPath, readValue) != Status::SUCCESS)
        {
            ALOGE("failed to read port status of %s at %s",
                  port.name.c_str(),
                  portModeFilesystemPath.c_str());

            return Status::ERROR;
        }

        ALOGV("mode %s", readValue.c_str());

        if (readValue == "host") {
            status.currentPowerRole = PortPowerRole::SOURCE;
            status.currentDataRole = PortDataRole::HOST;
            status.currentMode = PortMode::DFP;
        } else if (readValue == "peripheral") {
            status.currentPowerRole = PortPowerRole::SINK;
            status.currentDataRole = PortDataRole::DEVICE;
            status.currentMode = PortMode::UFP;
        } else {
            ALOGE("unrecognized status of port %s (%s)",
                  port.name.c_str(),
                  readValue.c_str());
            return Status::ERROR;
        }
    }

    // fill the rest of the details
    status.portName = port.name;

    status.canChangeMode = port.canChangeMode;
    status.canChangeDataRole = port.canChangeDataRole;
    status.canChangePowerRole = port.canChangePowerRole;
    status.supportedModes = port.mode;

    ALOGV("%s: canChangeMode: %d canChangedata: %d canChangePower:%d",
          status.portName.c_str(),
          status.canChangeMode,
          status.canChangeDataRole,
          status.canChangePowerRole);

    return Status::SUCCESS;
}

Status Usb::getPortStatusVec(hidl_vec<PortStatus>& currentPortStatus)
{
    currentPortStatus.resize(mUsbConfig.availablePorts.size());

    int index = 0;
    for(const auto& portMapPair : mUsbConfig.availablePorts) {
        PortStatus newStatus;

        if(getSinglePortStatus(portMapPair.second, newStatus) != Status::SUCCESS) {
            ALOGE("error while querying port %s", portMapPair.first.c_str());
            return Status::ERROR;
        }

        currentPortStatus[index] = newStatus;
        index++;
    }

    return Status::SUCCESS;
}

/// IUsb implementation

Return<void> Usb::switchRole(const hidl_string& portName, const PortRole& newRole)
{
    ALOGV("switchRole called: portName: %s, role: %d:%u",
          portName.c_str(),
          (int) newRole.type,
          newRole.role);

    if (mCallback == NULL) {
        ALOGW("switchRole: no callback set");
        return Void();
    }

    Status switchStatus = Status::ERROR;
    std::string portNameStr = portName.c_str();

    // skip empty or nonexisting ports
    if(portName.empty() || !mUsbConfig.availablePorts.count(portNameStr)) {
        ALOGW("switchRole: attempt to switch nonexisting port %s", portName.c_str());
    } else {
        auto portEntry = mUsbConfig.availablePorts.at(portNameStr);

        // check if the switch is allowed
        if (newRole.type == PortRoleType::POWER_ROLE && !portEntry.canChangePowerRole) {
            ALOGW("switchRole: can't change PowerRole for port %s", portName.c_str());
        } else if (newRole.type == PortRoleType::DATA_ROLE && !portEntry.canChangeDataRole) {
            ALOGW("switchRole: can't change DataRole for port %s", portName.c_str());
        } else if (newRole.type == PortRoleType::MODE && !portEntry.canChangeMode) {
            ALOGW("switchRole: can't change PortMode for port %s", portName.c_str());
        } else {
            std::string portModeFilesystemPath = SYS_USB_PATH + portNameStr + "/role";
            std::string newRoleString = convertToRoleString(newRole);

            if(!newRoleString.empty()) {
                switchStatus = writeFile(portModeFilesystemPath, newRoleString);
                if(switchStatus == Status::ERROR) {
                    ALOGE("switchRole failed: failed to write %s to a file %s",
                        newRoleString.c_str(),
                        portModeFilesystemPath.c_str());
                }
            } else {
                ALOGE("switchRole failed: unknown role to switch");
            }
        }
    }
    Return<void> ret = mCallback->notifyRoleSwitchStatus(portName, newRole, switchStatus);
    if (!ret.isOk())
        ALOGE("RoleSwitchStatus error %s", ret.description().c_str());

    return Void();
}

Return<void> Usb::queryPortStatus()
{
    ALOGV("queryPortStatus called");

    if (mCallback == NULL) {
        ALOGW("queryPortStatus: no callback set");
        return Void();
    }

    hidl_vec<PortStatus> currentPortStatus;
    Status status;

    if(!mUsbConfig.isConfigRead) {
        if(mUsbConfig.readConfigFromXML() != Status::SUCCESS)
        {
            ALOGE("queryPortStatus failed: missing config");
            return Void();
        }
    }

    status = getPortStatusVec(currentPortStatus);
    Return<void> ret = mCallback->notifyPortStatusChange(currentPortStatus, status);

    if (!ret.isOk())
        ALOGE("PortStatusChange error %s", ret.description().c_str());

    return Void();
}


// Set by the signal handler to destroy the thread
volatile bool destroyThread;
void sighandler(int sig);
void* work(void* param);

Return<void> Usb::setCallback(const sp<IUsbCallback>& callback)
{
    ALOGV("setCallback called");

    pthread_mutex_lock(&mLock);
    if ((mCallback == NULL && callback == NULL) ||
            (mCallback != NULL && callback != NULL)) {
        mCallback = callback;
        pthread_mutex_unlock(&mLock);
        return Void();
    }

    mCallback = callback;
    ALOGI("registering callback");

    if (mCallback == NULL) {
        if  (!pthread_kill(mPoll, SIGUSR1)) {
            pthread_join(mPoll, NULL);
            ALOGI("pthread destroyed");
        }
        pthread_mutex_unlock(&mLock);
        return Void();
    }

    destroyThread = false;
    signal(SIGUSR1, sighandler);

    if (pthread_create(&mPoll, NULL, work, this)) {
        ALOGE("pthread creation failed %d", errno);
        mCallback = NULL;
    }
    pthread_mutex_unlock(&mLock);
    return Void();
}

/// UEVENT handling

struct data
{
    int uevent_fd;
    android::hardware::usb::V1_0::implementation::Usb *usb;
};

void sighandler(int sig)
{
    if (sig == SIGUSR1) {
        destroyThread = true;
        ALOGI("destroy set");
        return;
    }
    signal(SIGUSR1, sighandler);
}

// TODO: manage uevents properly
static void uevent_event(uint32_t /*epevents*/, struct data *payload)
{
    char msg[UEVENT_MSG_LEN + 2];
    char *cp;
    int n;

    n = uevent_kernel_multicast_recv(payload->uevent_fd, msg, UEVENT_MSG_LEN);
    if (n <= 0)
        return;
    if (n >= UEVENT_MSG_LEN)   /* overflow -- discard */
        return;

    msg[n] = '\0';
    msg[n + 1] = '\0';
    cp = msg;

    while (*cp) {
        if (!strcmp(cp, "SUBSYSTEM=usb")
            || !strcmp(cp, "SUBSYSTEM=android_usb")
            || !strcmp(cp, "SUBSYSTEM=extcon")) {
            ALOGI("uevent received %s", cp);
            payload->usb->queryPortStatus();
            break;
        }

        /* advance to after the next \0 */
        while (*cp++);
    }
}

void* work(void* param)
{
    int epoll_fd, uevent_fd;
    struct epoll_event ev;
    int nevents = 0;
    struct data payload;

    ALOGE("creating thread");

    uevent_fd = uevent_open_socket(64*1024, true);

    if (uevent_fd < 0) {
        ALOGE("uevent_init: uevent_open_socket failed\n");
        return NULL;
    }

    payload.uevent_fd = uevent_fd;
    payload.usb = (android::hardware::usb::V1_0::implementation::Usb *)param;

    fcntl(uevent_fd, F_SETFL, O_NONBLOCK);

    ev.events = EPOLLIN;
    ev.data.ptr = (void *)uevent_event;

    epoll_fd = epoll_create(64);
    if (epoll_fd == -1) {
        ALOGE("epoll_create failed; errno=%d", errno);
        goto error;
    }

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, uevent_fd, &ev) == -1) {
        ALOGE("epoll_ctl failed; errno=%d", errno);
        goto error;
    }

    while (!destroyThread) {
        struct epoll_event events[64];

        nevents = epoll_wait(epoll_fd, events, 64, -1);
        if (nevents == -1) {
            if (errno == EINTR)
                continue;
            ALOGE("usb epoll_wait failed; errno=%d", errno);
            break;
        }

        for (int n = 0; n < nevents; ++n) {
            if (events[n].data.ptr)
                (*(void (*)(int, struct data *payload))events[n].data.ptr)
                    (events[n].events, &payload);
        }
    }

    ALOGI("exiting worker thread");
error:
    close(uevent_fd);

    if (epoll_fd >= 0)
        close(epoll_fd);

    return NULL;
}

// Protects *usb assignment
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
Usb *usb;

Usb::Usb()
{
    pthread_mutex_lock(&lock);
    // Make this a singleton class
    assert(usb == NULL);
    usb = this;
    pthread_mutex_unlock(&lock);
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace usb
}  // namespace hardware
}  // namespace android
