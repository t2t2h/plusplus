TARGET := iphone:clang:latest:14.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

# مكتبة مستقلة (dylib) بدون أي اعتماد على Substrate / ElleKit
LIBRARY_NAME = AflatoonSuite

AflatoonSuite_FILES = Tweak.xm
AflatoonSuite_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
AflatoonSuite_FRAMEWORKS = UIKit Foundation QuartzCore AVFoundation
AflatoonSuite_LOGOS_DEFAULT_GENERATOR = internal
AflatoonSuite_USE_SUBSTRATE = 0

# إصلاح خطأ الربط: "Shared cache eligible dylib cannot link to ineligible dylib CydiaSubstrate"
# 1) -not_for_dyld_shared_cache : يوقف فحص أهلية الـ shared cache الذي كان يُفشل الربط
# 2) -dead_strip_dylibs         : يحذف أي مكتبة مربوطة ولا يُستخدم منها شيء (Substrate)
AflatoonSuite_LDFLAGS += -Wl,-not_for_dyld_shared_cache -Wl,-dead_strip_dylibs

include $(THEOS_MAKE_PATH)/library.mk
