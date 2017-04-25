LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := dirtycow
LOCAL_SRC_FILES := \
	dirtycow.c
LOCAL_CFLAGS += -DDEBUG
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_SDK_VERSION := 21
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := cow-run-as
LOCAL_MODULE_FILE := run-as
LOCAL_SRC_FILES := \
	run-as.c
LOCAL_SDK_VERSION := 21
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := recowvery-applypatch
LOCAL_SRC_FILES := \
	recowvery-applypatch.c
LOCAL_C_INCLUDES := external/libbootimg
LOCAL_CFLAGS += -DDEBUG -Os
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_STATIC_LIBRARIES := libbootimg-static
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := recowvery-applyzero
LOCAL_SRC_FILES := \
	recowvery-applyzero.c
LOCAL_C_INCLUDES := external/libbootimg
LOCAL_CFLAGS += -DDEBUG -Os
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_STATIC_LIBRARIES := libbootimg-static
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := recowvery-app_process
LOCAL_MODULE_STEM_32 := recowvery-app_process32
LOCAL_MODULE_STEM_64 := recowvery-app_process64
LOCAL_MULTIBIT := true
LOCAL_SRC_FILES := \
	recowvery-app_process.c
LOCAL_CFLAGS += -DDEBUG -Os
LOCAL_CFLAGS_64 := -D_64BIT
LOCAL_SHARED_LIBRARIES := liblog libcutils libselinux
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := recowvery-app_process2
LOCAL_MODULE_STEM_32 := recowvery-app_process2_32
LOCAL_MODULE_STEM_64 := recowvery-app_process2_64
LOCAL_MULTIBIT := true
LOCAL_SRC_FILES := \
	recowvery-app_process2.c
LOCAL_CFLAGS += -DDEBUG -Os
LOCAL_CFLAGS_64 := -D_64BIT
LOCAL_SHARED_LIBRARIES := liblog libcutils libselinux
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := recowvery-run-as
LOCAL_SRC_FILES := \
	recowvery-run-as.c
LOCAL_CFLAGS += -Os
LOCAL_SHARED_LIBRARIES := libselinux
include $(BUILD_EXECUTABLE)
