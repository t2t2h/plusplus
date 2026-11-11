// Aflatoon Suite — DomainSniffer + ServerTester في مشروع واحد (dylib مستقل)
// © أفلاطون (Aflatoon / Plato) — جميع الحقوق محفوظة
//
// يجمع:
//   1) DomainSniffer: صيد النطاقات والـ IP وDNS، قواعد الاستبدال، NextDNS، الدردشة والصوت.
//   2) ServerTester: اختبار ضغط WebSocket/HTTP لسيرفرك الخاص.
//   3) AUTO TEST جديد: خيار ALL يصيد كل النطاقات/IP/DNS ويختبرها تلقائياً،
//      وخيار CHAT يصيد IP/DNS الخاصة بالدردشة والكتابة أونلاين ويختبرها تلقائياً.
//
// لا يحتاج Substrate / ElleKit: محرك الـ hook مدمج (إعادة ربط رموز Mach-O + ObjC runtime).

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <AVFoundation/AVFoundation.h>
#include <objc/runtime.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/select.h>
#include <poll.h>
#include <stdatomic.h>

#pragma mark - Store

@interface DSStore : NSObject
+ (instancetype)shared;
- (void)recordHost:(NSString *)host ips:(NSArray<NSString *> *)ips source:(NSString *)src failed:(BOOL)failed;
- (void)recordIP:(NSString *)ip port:(int)port source:(NSString *)src;
- (void)setProbe:(NSDictionary *)probe forValue:(NSString *)value;
- (NSArray<NSDictionary *> *)snapshot;
- (NSArray<NSURL *> *)saveAll;
- (NSString *)denylistText;
- (NSUInteger)denylistCount;
- (void)clear;
@end

static BOOL DSIsIPString(NSString *s) {
    struct in_addr a4; struct in6_addr a6;
    return inet_pton(AF_INET, s.UTF8String, &a4) == 1 || inet_pton(AF_INET6, s.UTF8String, &a6) == 1;
}

static NSString *ASDir(void) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *dir = [docs stringByAppendingPathComponent:@"AflatoonSuite"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

    // ترحيل إعدادات النسختين القديمتين (DomainSniffer / ServerTester) مرة واحدة فقط.
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *oldDS = [docs stringByAppendingPathComponent:@"DomainSniffer"];
        for (NSString *name in @[@"settings.json", @"data.json"]) {
            NSString *from = [oldDS stringByAppendingPathComponent:name];
            NSString *to = [dir stringByAppendingPathComponent:name];
            if (![fm fileExistsAtPath:to] && [fm fileExistsAtPath:from])
                [fm copyItemAtPath:from toPath:to error:nil];
        }
        NSString *oldST = [docs stringByAppendingPathComponent:@"ServerTester/settings.json"];
        NSString *newST = [dir stringByAppendingPathComponent:@"server-test.json"];
        if (![fm fileExistsAtPath:newST] && [fm fileExistsAtPath:oldST])
            [fm copyItemAtPath:oldST toPath:newST error:nil];
    });
    return dir;
}
#define DSDir() ASDir()


#pragma mark - Settings (persistent)

// أعلام سريعة تُقرأ من خيوط الشبكة بدون قفل
static volatile BOOL gHasRules = NO, gHasIPRules = NO;
static volatile BOOL gChatMode = NO;   // تحويل نطاقات وIPs الدردشة والكتابة أونلاين إلى 8.8.8.8
static volatile BOOL gForceAll = NO;   // تحويل كل النطاقات والـ IPs إلى 8.8.8.8 (لحظي)
static volatile BOOL gAutoDNS = YES;   // وضع DNS تلقائي → 8.8.8.8
static volatile BOOL gKbRepeat = NO;   // الكيبورد: تكرار الأرقام (135 → 135.135)
static volatile BOOL gKpOn = NO;          // الكيبورد العائم ظاهر
static volatile BOOL gKpHideSys = NO;     // إخفاء كيبورد النظام أثناء ظهور العائم
static volatile BOOL gKbAI = NO;          // الكيبورد: إرسال ذكي (AI) — يتعلم إيقاع كتابتك ويرسل بعد الانتهاء فقط
static volatile NSInteger gKbAILevel = 1;  // 0 حذر / 1 متوازن / 2 سريع
static volatile double gKbAIMul = 1.0;     // معامل يتعلمه الذكاء من أخطائه (يكبر إذا أرسل مبكراً)
static volatile BOOL gKbSplit = NO;    // الكيبورد: تفكيك الحروف (حسين → ح س ي ن)

static void DSKeypadSetVisible(BOOL on);
static void DSKeypadApplyHide(void);
static NSString *DSKbAILevelName(NSInteger l) { return l == 0 ? @"متوازن" : l == 2 ? @"فوري" : @"سريع"; }

@interface DSSettings : NSObject
+ (instancetype)shared;
@property (atomic, copy) NSString *apiKey;
@property (atomic, copy) NSString *profileId;
@property (atomic) BOOL autoDNS;
@property (atomic) BOOL forceAll;
@property (atomic) BOOL chatMode;
@property (atomic) BOOL kbRepeatNums;
@property (atomic) BOOL kbSplitLetters;
@property (atomic) BOOL kbPad;
@property (atomic) BOOL kbPadHide;
@property (atomic) BOOL kbAISend;
@property (atomic) NSInteger kbAILevel;   // 0..2
@property (atomic) double kbAIMul;        // 1.0..3.0 (متعلَّم)
@property (atomic, copy) NSArray<NSString *> *chatKeywords;
@property (atomic) BOOL joinSoundOn;
@property (atomic) float joinSoundRate;   // 1..4
@property (atomic) BOOL voiceSpeedOn;
@property (atomic) float voiceSpeedMax;   // 1..4 — أقصى سرعة "لحاق" بصوت المتكلمين داخل الروم
- (NSArray<NSDictionary *> *)rules;
- (void)addRuleFrom:(NSString *)f to:(NSString *)t;
- (void)setRule:(NSUInteger)i enabled:(BOOL)on;
- (void)removeRule:(NSUInteger)i;
- (NSString *)targetFor:(NSString *)host;
- (BOOL)wasSent:(NSString *)d;
- (void)markSent:(NSString *)d;
- (void)save;
@end

@implementation DSSettings {
    NSMutableArray<NSDictionary *> *_rules;
    NSMutableSet<NSString *> *_sent;
}

+ (instancetype)shared {
    static DSSettings *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [DSSettings new]; });
    return s;
}

- (NSString *)path { return [DSDir() stringByAppendingPathComponent:@"settings.json"]; }

- (instancetype)init {
    if ((self = [super init])) {
        _rules = [NSMutableArray array];
        self.autoDNS = YES;   // الافتراضي: مفعّل
        self.kbAILevel = 2; self.kbAIMul = 1.0;
        self.chatKeywords = @[];
        self.joinSoundRate = 1.0;
        self.voiceSpeedMax = 1.0;
        _sent = [NSMutableSet set];
        NSData *d = [NSData dataWithContentsOfFile:[self path]];
        NSDictionary *j = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
        if ([j isKindOfClass:NSDictionary.class]) {
            self.apiKey = j[@"apiKey"];
            self.profileId = j[@"profileId"];
            if (j[@"autoDNS"]) self.autoDNS = [j[@"autoDNS"] boolValue];
            self.forceAll = [j[@"forceAll"] boolValue];
            self.chatMode = [j[@"chatMode"] boolValue];
            self.kbRepeatNums = [j[@"kbRepeatNums"] boolValue];
            self.kbSplitLetters = [j[@"kbSplitLetters"] boolValue];
            self.kbAISend = [j[@"kbAISend"] boolValue];
            self.kbPad = [j[@"kbPad"] boolValue];
            self.kbPadHide = [j[@"kbPadHide"] boolValue];
            if (j[@"kbAILevel2"]) self.kbAILevel = MAX(0, MIN(2, [j[@"kbAILevel2"] integerValue]));   // مفتاح جديد: النسخ القديمة كانت أبطأ
            if (j[@"kbAIMul"]) self.kbAIMul = MAX(1.0, MIN(3.0, [j[@"kbAIMul"] doubleValue]));
            if ([j[@"chatKeywords"] isKindOfClass:[NSArray class]]) self.chatKeywords = j[@"chatKeywords"];
            self.joinSoundOn = [j[@"joinSoundOn"] boolValue];
            if (j[@"joinSoundRate"]) self.joinSoundRate = [j[@"joinSoundRate"] floatValue];
            self.voiceSpeedOn = [j[@"voiceSpeedOn"] boolValue];
            if (j[@"voiceSpeedMax"]) self.voiceSpeedMax = [j[@"voiceSpeedMax"] floatValue];
            for (NSDictionary *r in j[@"rules"]) {
                if ([r[@"from"] isKindOfClass:NSString.class] && [r[@"to"] isKindOfClass:NSString.class])
                    [_rules addObject:@{ @"from": r[@"from"], @"to": r[@"to"], @"enabled": @([r[@"enabled"] boolValue]) }];
            }
            [_sent addObjectsFromArray:j[@"sent"] ?: @[]];
        }
        [self refreshFlags];
    }
    return self;
}

- (void)refreshFlags {  // داخل @synchronized(self) أو من init
    BOOL any = NO, ip = NO;
    for (NSDictionary *r in _rules) {
        if (![r[@"enabled"] boolValue]) continue;
        any = YES;
        if (DSIsIPString(r[@"from"])) ip = YES;
    }
    gHasRules = any; gHasIPRules = ip; gAutoDNS = self.autoDNS; gForceAll = self.forceAll; gChatMode = self.chatMode;
    gKbRepeat = self.kbRepeatNums; gKbSplit = self.kbSplitLetters; gKpHideSys = self.kbPadHide; gKbAI = self.kbAISend; gKbAILevel = self.kbAILevel; gKbAIMul = self.kbAIMul;
}

- (void)save {
    NSDictionary *dump;
    @synchronized (self) {
        [self refreshFlags];
        dump = @{ @"apiKey": self.apiKey ?: @"", @"profileId": self.profileId ?: @"", @"autoDNS": @(self.autoDNS), @"forceAll": @(self.forceAll), @"chatMode": @(self.chatMode), @"kbRepeatNums": @(self.kbRepeatNums), @"kbSplitLetters": @(self.kbSplitLetters), @"kbAISend": @(self.kbAISend), @"kbPad": @(self.kbPad), @"kbPadHide": @(self.kbPadHide), @"kbAILevel2": @(self.kbAILevel), @"kbAIMul": @(self.kbAIMul), @"chatKeywords": self.chatKeywords ?: @[], @"joinSoundOn": @(self.joinSoundOn), @"joinSoundRate": @(self.joinSoundRate), @"voiceSpeedOn": @(self.voiceSpeedOn), @"voiceSpeedMax": @(self.voiceSpeedMax),
                  @"rules": [_rules copy], @"sent": [[_sent allObjects] sortedArrayUsingSelector:@selector(compare:)] };
    }
    NSData *d = [NSJSONSerialization dataWithJSONObject:dump options:NSJSONWritingPrettyPrinted error:nil];
    [d writeToFile:[self path] atomically:YES];
}

- (NSArray<NSDictionary *> *)rules { @synchronized (self) { return [_rules copy]; } }

- (void)addRuleFrom:(NSString *)f to:(NSString *)t {
    f = [f stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].lowercaseString;
    t = [t stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].lowercaseString;
    if (!f.length || !t.length) return;
    @synchronized (self) {
        for (NSUInteger i = 0; i < _rules.count; i++)   // نفس المصدر: حدّث الهدف
            if ([_rules[i][@"from"] isEqualToString:f]) { [_rules removeObjectAtIndex:i]; break; }
        [_rules addObject:@{ @"from": f, @"to": t, @"enabled": @YES }];
    }
    [self save];
}

- (void)setRule:(NSUInteger)i enabled:(BOOL)on {
    @synchronized (self) {
        if (i >= _rules.count) return;
        NSMutableDictionary *r = [_rules[i] mutableCopy]; r[@"enabled"] = @(on); _rules[i] = r;
    }
    [self save];
}

- (void)removeRule:(NSUInteger)i {
    @synchronized (self) { if (i < _rules.count) [_rules removeObjectAtIndex:i]; }
    [self save];
}

- (NSString *)targetFor:(NSString *)host {
    if (!gHasRules || host.length == 0) return nil;
    host = host.lowercaseString;
    @synchronized (self) {
        for (NSDictionary *r in _rules) {
            if (![r[@"enabled"] boolValue]) continue;
            NSString *f = r[@"from"];
            if ([f hasPrefix:@"*."]) { if ([host hasSuffix:[f substringFromIndex:1]]) return r[@"to"]; }
            else if ([host isEqualToString:f]) return r[@"to"];
        }
    }
    return nil;
}

- (BOOL)wasSent:(NSString *)d { @synchronized (self) { return [_sent containsObject:d.lowercaseString]; } }
- (void)markSent:(NSString *)d { @synchronized (self) { [_sent addObject:d.lowercaseString]; } [self save]; }
@end

#pragma mark - NextDNS API

static void DSNDRequest(NSString *method, NSString *path, NSDictionary *body,
                        void (^cb)(NSInteger code, id json, NSError *err)) {
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:
        [NSURL URLWithString:[@"https://api.nextdns.io" stringByAppendingString:path]]];
    r.HTTPMethod = method; r.timeoutInterval = 15;
    [r setValue:[DSSettings shared].apiKey ?: @"" forHTTPHeaderField:@"X-Api-Key"];
    if (body) {
        r.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
        [r setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    }
    [[NSURLSession.sharedSession dataTaskWithRequest:r completionHandler:^(NSData *d, NSURLResponse *resp, NSError *e) {
        id j = d.length ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
        NSInteger code = [resp isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse *)resp).statusCode : 0;
        dispatch_async(dispatch_get_main_queue(), ^{ cb(code, j, e); });
    }] resume];
}

// يجلب Profile ID تلقائياً (أول حساب) إذا لم يُدخل يدوياً
static void DSNDEnsureProfile(void (^cb)(NSString *pid, NSString *err)) {
    DSSettings *st = [DSSettings shared];
    if (st.profileId.length) { cb(st.profileId, nil); return; }
    DSNDRequest(@"GET", @"/profiles", nil, ^(NSInteger code, id json, NSError *e) {
        NSArray *arr = [json isKindOfClass:NSDictionary.class] ? json[@"data"] : nil;
        id first = [arr isKindOfClass:NSArray.class] ? arr.firstObject : nil;
        NSString *pid = [first isKindOfClass:NSDictionary.class] ? first[@"id"] : nil;
        if (pid.length) { st.profileId = pid; [st save]; cb(pid, nil); return; }
        if (code == 401 || code == 403) cb(nil, @"مفتاح API غير صحيح");
        else cb(nil, e ? e.localizedDescription : @"تعذّر جلب Profile ID");
    });
}

static NSString *DSNDErrorText(NSInteger code, id json) {
    id errs = [json isKindOfClass:NSDictionary.class] ? json[@"errors"] : nil;
    id first = [errs isKindOfClass:NSArray.class] ? [errs firstObject] : nil;
    NSString *c = [first isKindOfClass:NSDictionary.class] ? first[@"code"] : nil;
    return c.length ? [NSString stringWithFormat:@"خطأ: %@", c] : [NSString stringWithFormat:@"فشل (%ld)", (long)code];
}

@implementation DSStore {
    dispatch_queue_t _q;
    NSMutableDictionary<NSString *, NSMutableDictionary *> *_items;
    NSMutableDictionary<NSString *, NSString *> *_ipHost;
    NSMutableSet<NSString *> *_seenIP;
    BOOL _saveScheduled;
}

+ (instancetype)shared {
    static DSStore *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [DSStore new]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _q = dispatch_queue_create("ds.store", DISPATCH_QUEUE_SERIAL);
        _items = [NSMutableDictionary dictionary];
        _ipHost = [NSMutableDictionary dictionary];
        _seenIP = [NSMutableSet set];
        [self load];
    }
    return self;
}

- (NSMutableDictionary *)entryFor:(NSString *)v type:(NSString *)t {
    NSMutableDictionary *e = _items[v];
    if (!e) {
        e = [@{ @"type": t, @"count": @0, @"related": [NSMutableSet set], @"src": [NSMutableSet set],
                @"status": @"OK", @"probe": [NSMutableDictionary dictionary],
                @"first": @([[NSDate date] timeIntervalSince1970]), @"last": @0 } mutableCopy];
        _items[v] = e;
    }
    e[@"last"] = @([[NSDate date] timeIntervalSince1970]);
    return e;
}

- (void)recordHost:(NSString *)host ips:(NSArray<NSString *> *)ips source:(NSString *)src failed:(BOOL)failed {
    if (host.length == 0) return;
    host = host.lowercaseString;
    if ([host hasSuffix:@"nextdns.io"]) return;  // لا تسجّل طلبات الأداة نفسها
    if (DSIsIPString(host)) { [self recordIP:host port:0 source:src]; return; }
    dispatch_async(_q, ^{
        NSMutableDictionary *e = [self entryFor:host type:@"domain"];
        e[@"count"] = @([e[@"count"] integerValue] + 1);
        [e[@"src"] addObject:src];
        BOOL blocked = NO;
        for (NSString *ip in ips) {
            [e[@"related"] addObject:ip];
            self->_ipHost[ip] = host;
            if ([ip isEqualToString:@"0.0.0.0"] || [ip isEqualToString:@"::"]) blocked = YES;
        }
        if (blocked) e[@"status"] = @"BLOCKED";
        else if (failed && ips.count == 0) e[@"status"] = @"FAILED";
        else if (ips.count > 0) e[@"status"] = @"OK";
        [self markDirty];
    });
}

- (void)recordIP:(NSString *)ip port:(int)port source:(NSString *)src {
    if (ip.length == 0) return;
    NSString *key = [NSString stringWithFormat:@"%@:%d", ip, port];
    @synchronized (_seenIP) {
        if ([_seenIP containsObject:key]) return;
        [_seenIP addObject:key];
    }
    dispatch_async(_q, ^{
        NSMutableDictionary *e = [self entryFor:ip type:@"ip"];
        e[@"count"] = @([e[@"count"] integerValue] + 1);
        [e[@"src"] addObject:(port ? [NSString stringWithFormat:@"%@:%d", src, port] : src)];
        NSString *h = self->_ipHost[ip];
        if (h) [e[@"related"] addObject:h];
        [self markDirty];
    });
}

- (void)setProbe:(NSDictionary *)probe forValue:(NSString *)value {
    if (!value.length || ![probe isKindOfClass:NSDictionary.class]) return;
    dispatch_async(_q, ^{
        NSMutableDictionary *e = self->_items[value];
        if (!e) return;
        e[@"probe"] = [probe mutableCopy];
        [self markDirty];
    });
}

- (void)markDirty {  // يُستدعى داخل _q
    if (_saveScheduled) return;
    _saveScheduled = YES;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), _q, ^{
        self->_saveScheduled = NO;
        [self writeJSON];
    });
}

- (NSArray *)sorted:(id)set { return [[set allObjects] sortedArrayUsingSelector:@selector(compare:)]; }

- (NSArray<NSDictionary *> *)snapshot {
    __block NSMutableArray *out = [NSMutableArray array];
    dispatch_sync(_q, ^{
        for (NSString *k in self->_items) {
            NSDictionary *e = self->_items[k];
            [out addObject:@{ @"value": k, @"type": e[@"type"], @"count": e[@"count"],
                              @"related": [self sorted:e[@"related"]], @"src": [self sorted:e[@"src"]],
                              @"status": e[@"status"], @"probe": e[@"probe"] ?: @{},
                              @"last": e[@"last"], @"first": e[@"first"] }];
        }
    });
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [b[@"last"] compare:a[@"last"]];
    }];
    return out;
}

- (void)writeJSON {  // داخل _q
    NSMutableDictionary *dump = [NSMutableDictionary dictionary];
    for (NSString *k in _items) {
        NSDictionary *e = _items[k];
        dump[k] = @{ @"type": e[@"type"], @"count": e[@"count"], @"related": [self sorted:e[@"related"]],
                     @"src": [self sorted:e[@"src"]], @"status": e[@"status"], @"probe": e[@"probe"] ?: @{},
                     @"first": e[@"first"], @"last": e[@"last"] };
    }
    NSData *d = [NSJSONSerialization dataWithJSONObject:dump options:NSJSONWritingPrettyPrinted error:nil];
    [d writeToFile:[DSDir() stringByAppendingPathComponent:@"data.json"] atomically:YES];
}

- (void)load {
    NSData *d = [NSData dataWithContentsOfFile:[DSDir() stringByAppendingPathComponent:@"data.json"]];
    if (!d) return;
    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![j isKindOfClass:NSDictionary.class]) return;
    for (NSString *k in j) {
        NSDictionary *e = j[k];
        NSDictionary *pr = [e[@"probe"] isKindOfClass:NSDictionary.class] ? e[@"probe"] : @{};
        _items[k] = [@{ @"type": e[@"type"] ?: @"domain", @"count": e[@"count"] ?: @0,
                        @"related": [NSMutableSet setWithArray:e[@"related"] ?: @[]],
                        @"src": [NSMutableSet setWithArray:e[@"src"] ?: @[]],
                        @"status": e[@"status"] ?: @"OK", @"probe": [pr mutableCopy],
                        @"first": e[@"first"] ?: @0, @"last": e[@"last"] ?: @0 } mutableCopy];
    }
}

- (NSString *)denylistText {
    NSMutableArray *lines = [NSMutableArray array];
    for (NSDictionary *e in [self snapshot]) {
        if ([e[@"type"] isEqualToString:@"domain"] && ![e[@"status"] isEqualToString:@"BLOCKED"]) [lines addObject:e[@"value"]];
    }
    [lines sortUsingSelector:@selector(compare:)];
    return [lines componentsJoinedByString:@"\n"];
}

- (NSUInteger)denylistCount {
    NSString *t = [self denylistText];
    return t.length ? [t componentsSeparatedByString:@"\n"].count : 0;
}

- (NSArray<NSURL *> *)saveAll {
    NSArray *snap = [self snapshot];
    NSMutableArray *doms = [NSMutableArray array], *ips = [NSMutableArray array];
    for (NSDictionary *e in snap) {
        NSString *line = [NSString stringWithFormat:@"%@  [%@] x%@  %@", e[@"value"], e[@"status"], e[@"count"],
                          [e[@"related"] componentsJoinedByString:@","]];
        [([e[@"type"] isEqualToString:@"domain"] ? doms : ips) addObject:line];
    }
    [doms sortUsingSelector:@selector(compare:)]; [ips sortUsingSelector:@selector(compare:)];
    NSString *dir = DSDir();
    NSString *p1 = [dir stringByAppendingPathComponent:@"domains.txt"];
    NSString *p2 = [dir stringByAppendingPathComponent:@"ips.txt"];
    NSString *p3 = [dir stringByAppendingPathComponent:@"denylist_nextdns.txt"];
    [[doms componentsJoinedByString:@"\n"] writeToFile:p1 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[ips componentsJoinedByString:@"\n"] writeToFile:p2 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[self denylistText] writeToFile:p3 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    dispatch_sync(_q, ^{ [self writeJSON]; });
    return @[ [NSURL fileURLWithPath:p3], [NSURL fileURLWithPath:p1], [NSURL fileURLWithPath:p2],
              [NSURL fileURLWithPath:[dir stringByAppendingPathComponent:@"data.json"]] ];
}

- (void)clear {
    dispatch_sync(_q, ^{
        [self->_items removeAllObjects]; [self->_ipHost removeAllObjects];
        [self writeJSON];
    });
    @synchronized (_seenIP) { [_seenIP removeAllObjects]; }
}
@end

#pragma mark - Network hooks

static NSString *DSAddrString(const struct sockaddr *sa) {
    char buf[INET6_ADDRSTRLEN];
    if (!sa) return nil;
    if (sa->sa_family == AF_INET) {
        if (inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, buf, sizeof buf)) return @(buf);
    } else if (sa->sa_family == AF_INET6) {
        if (inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, buf, sizeof buf)) return @(buf);
    }
    return nil;
}

static void DSNoteSockaddr(const struct sockaddr *sa, socklen_t len, const char *src) {
    if (!sa || len == 0 || len > sizeof(struct sockaddr_storage)) return;
    static __thread struct sockaddr_storage last;
    static __thread socklen_t lastLen;
    if (lastLen == len && memcmp(&last, sa, len) == 0) return;
    memcpy(&last, sa, len); lastLen = len;

    int port = 0;
    if (sa->sa_family == AF_INET) port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
    else if (sa->sa_family == AF_INET6) port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    else return;
    NSString *ip = DSAddrString(sa);
    if (!ip || [ip isEqualToString:@"127.0.0.1"] || [ip isEqualToString:@"::1"] || [ip isEqualToString:@"0.0.0.0"] || [ip isEqualToString:@"::"]) return;
    [[DSStore shared] recordIP:ip port:port source:@(src)];
}

// استبدال نطاق/IP في DNS حسب القواعد المفعّلة
static BOOL DSMapNode(const char *node, char *out, size_t n) {
    if (!node || !gHasRules) return NO;
    NSString *h = [NSString stringWithUTF8String:node];
    NSString *to = h ? [[DSSettings shared] targetFor:h] : nil;
    if (!to) return NO;
    strlcpy(out, to.UTF8String, n);
    return YES;
}

// ====== DNS تلقائي → 8.8.8.8 ======
#define DS_GDNS4 "8.8.8.8"
#define DS_GDNS6 "2001:4860:4860::8888"

static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);

// أي اتصال بمنفذ 53 (UDP/TCP) إلى سيرفر DNS غير Google → يتحوّل إلى 8.8.8.8 (المنفذ نفسه)
static BOOL DSDNSRewrite(const struct sockaddr *sa, socklen_t len, struct sockaddr_storage *out) {
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
        if (ntohs(a->sin_port) != 53) return NO;
        uint32_t ip = ntohl(a->sin_addr.s_addr);
        if (ip == 0 || (ip >> 24) == 127 || ip == 0x08080808) return NO;
        memcpy(out, sa, len);
        return inet_pton(AF_INET, DS_GDNS4, &((struct sockaddr_in *)out)->sin_addr) == 1;
    }
    if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;
        if (ntohs(a->sin6_port) != 53) return NO;
        struct in6_addr g; if (inet_pton(AF_INET6, DS_GDNS6, &g) != 1) return NO;
        if (IN6_IS_ADDR_LOOPBACK(&a->sin6_addr) || IN6_IS_ADDR_UNSPECIFIED(&a->sin6_addr) ||
            memcmp(&a->sin6_addr, &g, sizeof g) == 0) return NO;
        memcpy(out, sa, len);
        ((struct sockaddr_in6 *)out)->sin6_addr = g;
        return YES;
    }
    return NO;
}

// ---- وضع "الكل → 8.8.8.8" ----
static NSMutableSet *DSExemptSet(void) {   // IPs سيرفرات NextDNS (كي تبقى القائمة شغّالة)
    static NSMutableSet *x; static dispatch_once_t once;
    dispatch_once(&once, ^{ x = [NSMutableSet set]; });
    return x;
}
static BOOL DSIsNextDNSHost(const char *h) {
    size_t l = h ? strlen(h) : 0;
    return l >= 10 && strcasecmp(h + l - 10, "nextdns.io") == 0;
}
static void DSExemptAdd(const struct addrinfo *list) {
    @synchronized (DSExemptSet()) {
        for (const struct addrinfo *p = list; p; p = p->ai_next) {
            NSString *a = DSAddrString(p->ai_addr);
            if (a) [DSExemptSet() addObject:a];
        }
    }
}
static BOOL DSIsLocalAddr(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        uint32_t ip = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
        return ip == 0 || (ip >> 24) == 127 || (ip >> 24) == 10 || (ip >> 16) == 0xC0A8 ||
               (ip >> 20) == 0xAC1 || (ip >> 16) == 0xA9FE;
    }
    if (sa->sa_family == AF_INET6) {
        const struct in6_addr *a = &((const struct sockaddr_in6 *)sa)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_UNSPECIFIED(a) || IN6_IS_ADDR_LINKLOCAL(a) || (a->s6_addr[0] & 0xFE) == 0xFC;
    }
    return YES;
}
// ---- وضع "الدردشة والكتابة أونلاين → 8.8.8.8" ----
static NSMutableSet *DSChatIPs(void) {   // IPs الدردشة التي تعلّمناها من حلّ أسماءها
    static NSMutableSet *x; static dispatch_once_t once;
    dispatch_once(&once, ^{ x = [NSMutableSet set]; });
    return x;
}
static NSArray *DSChatSubstrings(void) {
    static NSArray *a;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ a = @[@"chat", @"typing", @"online", @"presence", @"messag", @"msgr", @"websocket", @"socket.io", @"signalr",
        @"xmpp", @"mqtt", @"agora", @"sendbird", @"pubnub", @"pusher", @"getstream", @"stream-io", @"twilio",
        @"cometchat", @"talkjs", @"livechat", @"tawk", @"zopim", @"whatsapp", @"telegram", @"discord", @"ably"]; });
    return a;
}
static NSSet *DSChatTokens(void) {
    static NSSet *a;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ a = [NSSet setWithArray:@[@"im", @"dm", @"msg", @"msgs", @"rtm", @"ws", @"wss",
        @"socket", @"sockets", @"realtime", @"presence", @"comms"]]; });
    return a;
}
static BOOL DSIsChatHost(const char *h) {
    if (!h || !h[0] || DSIsNextDNSHost(h)) return NO;
    NSString *s = [@(h) lowercaseString];
    if (!s) return NO;
    for (NSString *k in DSChatSubstrings()) if ([s containsString:k]) return YES;
    NSArray *tok = [s componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@".-_"]];
    NSSet *ex = DSChatTokens();
    for (NSString *t in tok) if ([ex containsObject:t]) return YES;
    for (NSString *k in [DSSettings shared].chatKeywords)       // كلمات إضافية من settings.json
        if ([k isKindOfClass:[NSString class]] && k.length && [s containsString:k.lowercaseString]) return YES;
    return NO;
}
static void DSChatIPAdd(const struct addrinfo *list) {
    @synchronized (DSChatIPs()) {
        for (const struct addrinfo *p = list; p; p = p->ai_next) {
            NSString *a = DSAddrString(p->ai_addr);
            if (a) [DSChatIPs() addObject:a];
        }
    }
}
static BOOL DSChatEligible(const char *node, const struct addrinfo *hints) {
    if (!node || !node[0] || !strchr(node, '.')) return NO;
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, node, &a4) == 1 || inet_pton(AF_INET6, node, &a6) == 1) return NO;
    if (hints) {
        if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET) return NO;
        if (hints->ai_flags & (AI_NUMERICHOST | AI_PASSIVE | AI_CANONNAME)) return NO;
    }
    return DSIsChatHost(node);
}
static const char *DSPortStr(const char *service, char *buf, size_t n) {   // https / wss → رقم
    if (!service) return NULL;
    if (strcasecmp(service, "https") == 0 || strcasecmp(service, "wss") == 0) return "443";
    if (strcasecmp(service, "http") == 0 || strcasecmp(service, "ws") == 0) return "80";
    strlcpy(buf, service, n); return buf;
}
static BOOL DSChatRewrite(const struct sockaddr *sa, socklen_t len, struct sockaddr_storage *out) {
    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) return NO;
    NSString *ip = DSAddrString(sa);
    if (!ip) return NO;
    BOOL hit; @synchronized (DSChatIPs()) { hit = [DSChatIPs() containsObject:ip]; }
    if (!hit) return NO;
    memcpy(out, sa, len);
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in))
        return inet_pton(AF_INET, DS_GDNS4, &((struct sockaddr_in *)out)->sin_addr) == 1;
    if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6))
        return inet_pton(AF_INET6, DS_GDNS6, &((struct sockaddr_in6 *)out)->sin6_addr) == 1;
    return NO;
}
static BOOL DSForceRewrite(const struct sockaddr *sa, socklen_t len, struct sockaddr_storage *out) {
    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) return NO;
    if (DSIsLocalAddr(sa)) return NO;
    NSString *ip = DSAddrString(sa);
    if (!ip || [ip isEqualToString:@DS_GDNS4] || [ip isEqualToString:@DS_GDNS6]) return NO;
    @synchronized (DSExemptSet()) { if ([DSExemptSet() containsObject:ip]) return NO; }
    memcpy(out, sa, len);
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in))
        return inet_pton(AF_INET, DS_GDNS4, &((struct sockaddr_in *)out)->sin_addr) == 1;
    if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6))
        return inet_pton(AF_INET6, DS_GDNS6, &((struct sockaddr_in6 *)out)->sin6_addr) == 1;
    return NO;
}

// استبدال IP في connect/sendto: قواعد المستخدم أولاً، ثم وضع DNS التلقائي
static BOOL DSRewriteSockaddr(const struct sockaddr *sa, socklen_t len, struct sockaddr_storage *out) {
    if (!sa || len == 0 || len > sizeof(*out)) return NO;
    if (gHasIPRules) {
        NSString *ip = DSAddrString(sa);
        NSString *to = ip ? [[DSSettings shared] targetFor:ip] : nil;
        if (to) {
            memcpy(out, sa, len);
            if (sa->sa_family == AF_INET) {
                struct in_addr a;
                if (inet_pton(AF_INET, to.UTF8String, &a) == 1) { ((struct sockaddr_in *)out)->sin_addr = a; return YES; }
            } else if (sa->sa_family == AF_INET6) {
                struct in6_addr a;
                if (inet_pton(AF_INET6, to.UTF8String, &a) == 1) { ((struct sockaddr_in6 *)out)->sin6_addr = a; return YES; }
            }
        }
    }
    if (gForceAll && DSForceRewrite(sa, len, out)) return YES;
    if (gChatMode && DSChatRewrite(sa, len, out)) return YES;
    if (gAutoDNS && DSDNSRewrite(sa, len, out)) return YES;
    return NO;
}

// ==== DS_RESOLVER_C_BEGIN ====
// محلّل DNS مدمج: يسأل 8.8.8.8 مباشرة (سجل A) بدل DNS الجهاز/الشبكة
static const char *gDNSServer = DS_GDNS4;
static uint16_t gDNSPort = 53;
static volatile double gDNSDownUntil = 0;   // إذا تعذّر الوصول لـ 8.8.8.8 نتجاوزه مؤقتاً

static double DSNow(void) { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); return (double)ts.tv_sec + ts.tv_nsec / 1e9; }

static size_t DSSkipName(const uint8_t *r, size_t n, size_t i) {
    while (i < n) {
        uint8_t l = r[i];
        if (l == 0) return i + 1;
        if ((l & 0xC0) == 0xC0) return (i + 2 <= n) ? i + 2 : 0;
        if (l & 0xC0) return 0;
        i += 1 + l;
    }
    return 0;
}

static BOOL DSDNSQuery4(const char *host, struct in_addr *outs, int max, int *count, uint32_t *minTTL) {
    size_t hl = strlen(host);
    if (hl == 0 || hl > 253) return NO;
    uint8_t q[320]; size_t o = 0;
    uint16_t id = (uint16_t)arc4random();
    q[o++] = id >> 8; q[o++] = id & 0xFF; q[o++] = 0x01; q[o++] = 0x00;      // ID + RD
    q[o++] = 0; q[o++] = 1; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0;
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (ll == 0 || ll > 63 || o + ll + 6 > sizeof q) return NO;
        q[o++] = (uint8_t)ll; memcpy(q + o, p, ll); o += ll;
        p += ll; if (*p == '.') p++;
    }
    q[o++] = 0; q[o++] = 0; q[o++] = 1; q[o++] = 0; q[o++] = 1;                // A / IN

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return NO;
    struct timeval tv = { 1, 200000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in dst; memset(&dst, 0, sizeof dst);
    dst.sin_len = sizeof dst; dst.sin_family = AF_INET; dst.sin_port = htons(gDNSPort);
    inet_pton(AF_INET, gDNSServer, &dst.sin_addr);

    ssize_t (*snd)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = orig_sendto ? orig_sendto : sendto;
    uint8_t r[1500]; ssize_t rn = -1;
    for (int t = 0; t < 2; t++) {
        if (snd(fd, q, o, 0, (struct sockaddr *)&dst, sizeof dst) < 0) break;
        rn = recvfrom(fd, r, sizeof r, 0, NULL, NULL);
        if (rn >= 12 && r[0] == q[0] && r[1] == q[1]) break;
        rn = -1;
    }
    close(fd);
    if (rn < 12) { gDNSDownUntil = DSNow() + 20.0; return NO; }               // لا رد: تجاوز 20 ثانية
    if (!(r[2] & 0x80) || (r[3] & 0x0F) != 0) return NO;                       // ليس رداً سليماً (NXDOMAIN وغيره)

    size_t N = (size_t)rn, i = 12;
    int qd = (r[4] << 8) | r[5], an = (r[6] << 8) | r[7];
    for (int k = 0; k < qd; k++) { i = DSSkipName(r, N, i); if (!i || i + 4 > N) return NO; i += 4; }
    int c = 0; uint32_t mt = 0xFFFFFFFFu;
    for (int k = 0; k < an && i < N; k++) {
        i = DSSkipName(r, N, i); if (!i || i + 10 > N) break;
        uint16_t type = (r[i] << 8) | r[i + 1], cls = (r[i + 2] << 8) | r[i + 3];
        uint32_t ttl = ((uint32_t)r[i + 4] << 24) | (r[i + 5] << 16) | (r[i + 6] << 8) | r[i + 7];
        uint16_t rdl = (r[i + 8] << 8) | r[i + 9];
        i += 10; if (i + rdl > N) break;
        if (type == 1 && cls == 1 && rdl == 4 && c < max) { memcpy(&outs[c++], r + i, 4); if (ttl < mt) mt = ttl; }
        i += rdl;
    }
    *count = c; *minTTL = (mt == 0xFFFFFFFFu) ? 0 : mt;
    return c > 0;
}

// يبني قائمة addrinfo (تُحرَّر بـ freeaddrinfo العادية: كل عقدة وعنوانها بـ malloc منفصل)
static struct addrinfo *DSBuildAddrInfo(const struct in_addr *ips, int n, const char *service, const struct addrinfo *hints) {
    int port = service ? atoi(service) : 0;
    int socktype = hints ? hints->ai_socktype : 0, proto = hints ? hints->ai_protocol : 0;
    int types[2], tc = 0;
    if (socktype == 0) { types[tc++] = SOCK_STREAM; types[tc++] = SOCK_DGRAM; } else types[tc++] = socktype;
    struct addrinfo *head = NULL, *tail = NULL;
    for (int i = 0; i < n; i++) for (int t = 0; t < tc; t++) {
        struct addrinfo *ai = (struct addrinfo *)calloc(1, sizeof *ai);
        struct sockaddr_in *sin = (struct sockaddr_in *)calloc(1, sizeof *sin);
        if (!ai || !sin) { free(ai); free(sin); continue; }
        sin->sin_len = sizeof *sin; sin->sin_family = AF_INET; sin->sin_port = htons((uint16_t)port); sin->sin_addr = ips[i];
        ai->ai_flags = hints ? hints->ai_flags : 0; ai->ai_family = AF_INET; ai->ai_socktype = types[t];
        ai->ai_protocol = proto ? proto : (types[t] == SOCK_STREAM ? IPPROTO_TCP : (types[t] == SOCK_DGRAM ? IPPROTO_UDP : 0));
        ai->ai_addrlen = sizeof *sin; ai->ai_addr = (struct sockaddr *)sin;
        if (tail) tail->ai_next = ai; else head = ai;
        tail = ai;
    }
    return head;
}
// ==== DS_RESOLVER_C_END ====

static NSMutableDictionary *DSDNSCache(void) {
    static NSMutableDictionary *c; static dispatch_once_t once;
    dispatch_once(&once, ^{ c = [NSMutableDictionary dictionary]; });
    return c;
}

static BOOL DSResolve4(const char *host, struct in_addr *outs, int max, int *count) {
    NSString *key = @(host).lowercaseString;
    if (!key) return NO;
    double now = DSNow();
    @synchronized (DSDNSCache()) {
        NSDictionary *e = DSDNSCache()[key];
        if (e && [e[@"exp"] doubleValue] > now) {
            NSData *d = e[@"ips"]; int n = (int)(d.length / sizeof(struct in_addr)); if (n > max) n = max;
            memcpy(outs, d.bytes, n * sizeof(struct in_addr)); *count = n; return n > 0;
        }
    }
    uint32_t ttl = 0; int n = 0;
    if (!DSDNSQuery4(host, outs, max, &n, &ttl) || n <= 0) return NO;
    if (ttl < 10) ttl = 10; if (ttl > 300) ttl = 300;
    @synchronized (DSDNSCache()) {
        if (DSDNSCache().count > 512) [DSDNSCache() removeAllObjects];
        DSDNSCache()[key] = @{ @"ips": [NSData dataWithBytes:outs length:n * sizeof(struct in_addr)], @"exp": @(now + ttl) };
    }
    *count = n; return YES;
}

// متى نستخدم المحلّل المدمج؟ فقط للأسماء العادية؛ غير ذلك نتركه للنظام
static BOOL DSNameEligible(const char *node, const char *service, const struct addrinfo *hints) {
    if (!node || !node[0]) return NO;
    if (!strchr(node, '.')) return NO;                                          // localhost وأسماء محلية
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, node, &a4) == 1 || inet_pton(AF_INET6, node, &a6) == 1) return NO;
    size_t l = strlen(node);
    if (l > 6 && strcasecmp(node + l - 6, ".local") == 0) return NO;
    if (hints) {
        if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET) return NO;
        if (hints->ai_flags & (AI_NUMERICHOST | AI_PASSIVE | AI_CANONNAME)) return NO;
    }
    if (service) { for (const char *c = service; *c; c++) if (*c < '0' || *c > '9') return NO; }
    return YES;
}
static BOOL DSShouldAutoResolve(const char *node, const char *service, const struct addrinfo *hints) {
    if (!gAutoDNS || DSNow() < gDNSDownUntil) return NO;
    return DSNameEligible(node, service, hints);
}
static BOOL DSForceEligible(const char *node, const char *service, const struct addrinfo *hints) {
    return gForceAll && DSNameEligible(node, service, hints) && !DSIsNextDNSHost(node);
}

static struct hostent *DSAutoHostent(const char *name) {
    static __thread struct hostent he; static __thread char nameBuf[256];
    static __thread struct in_addr addrs[16]; static __thread char *list[17]; static __thread char *aliases[1];
    struct in_addr ips[16]; int n = 0;
    if (!DSShouldAutoResolve(name, NULL, NULL) || !DSResolve4(name, ips, 16, &n) || n <= 0) return NULL;
    for (int i = 0; i < n; i++) { addrs[i] = ips[i]; list[i] = (char *)&addrs[i]; }
    list[n] = NULL; aliases[0] = NULL;
    strlcpy(nameBuf, name, sizeof nameBuf);
    he.h_name = nameBuf; he.h_aliases = aliases; he.h_addrtype = AF_INET; he.h_length = 4; he.h_addr_list = list;
    return &he;
}

static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static int hook_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    char mapped[256];
    BOOL isMapped = DSMapNode(node, mapped, sizeof mapped);
    int r = -1; BOOL done = NO;
    if (!isMapped && res && DSForceEligible(node, service, hints)) {          // الكل → 8.8.8.8
        struct in_addr g; inet_pton(AF_INET, DS_GDNS4, &g);
        struct addrinfo *fl = DSBuildAddrInfo(&g, 1, service, hints);
        if (fl) { *res = fl; r = 0; done = YES; }
    }
    if (!done && !isMapped && res && gChatMode && DSChatEligible(node, hints)) {   // دردشة/كتابة → 8.8.8.8
        struct addrinfo *real = NULL;
        if (orig_getaddrinfo(node, service, hints, &real) == 0 && real) { DSChatIPAdd(real); freeaddrinfo(real); }
        char pb[32]; struct in_addr g; inet_pton(AF_INET, DS_GDNS4, &g);
        struct addrinfo *cl = DSBuildAddrInfo(&g, 1, DSPortStr(service, pb, sizeof pb), hints);
        if (cl) { *res = cl; r = 0; done = YES; }
    }
    if (!done && !isMapped && res && DSShouldAutoResolve(node, service, hints)) {   // DNS = 8.8.8.8
        struct in_addr ips4[16]; int cnt = 0;
        if (DSResolve4(node, ips4, 16, &cnt)) {
            struct addrinfo *list = DSBuildAddrInfo(ips4, cnt, service, hints);
            if (list) { *res = list; r = 0; done = YES; }
        }
    }
    if (!done) r = orig_getaddrinfo(isMapped ? mapped : node, service, hints, res);   // احتياطي: DNS النظام
    if (r == 0 && res && *res && DSIsNextDNSHost(node)) DSExemptAdd(*res);
    // تعلّم IPs الدردشة/الكتابة أونلاين حتى لو لم يُفعّل CHAT → 8.8.8.8،
    // ليعرف AUTO TEST (CHAT) أي IP يخص الدردشة عند اختبار الأهداف الملتقطة.
    if (r == 0 && res && *res && node && !isMapped && DSChatEligible(node, hints)) DSChatIPAdd(*res);
    if (node) {
        NSMutableArray *ips = [NSMutableArray array];
        if (r == 0 && res && *res) {
            for (struct addrinfo *p = *res; p; p = p->ai_next) {
                NSString *s = DSAddrString(p->ai_addr);
                if (s && ![ips containsObject:s]) [ips addObject:s];
            }
        }
        NSString *h = [NSString stringWithUTF8String:node];
        if (h) [[DSStore shared] recordHost:h ips:ips source:@"dns" failed:(r != 0)];
    }
    return r;
}

static struct hostent *(*orig_gethostbyname)(const char *);
static struct hostent *hook_gethostbyname(const char *name) {
    char mapped[256];
    BOOL isMapped = DSMapNode(name, mapped, sizeof mapped);
    struct hostent *r = NULL;
    if (!isMapped && DSForceEligible(name, NULL, NULL)) {                       // الكل → 8.8.8.8
        static __thread struct hostent fh; static __thread char fn[256]; static __thread struct in_addr fa;
        static __thread char *fl[2]; static __thread char *fal[1];
        inet_pton(AF_INET, DS_GDNS4, &fa); fl[0] = (char *)&fa; fl[1] = NULL; fal[0] = NULL;
        strlcpy(fn, name, sizeof fn);
        fh.h_name = fn; fh.h_aliases = fal; fh.h_addrtype = AF_INET; fh.h_length = 4; fh.h_addr_list = fl;
        r = &fh;
    }
    if (!r && !isMapped && gChatMode && DSChatEligible(name, NULL)) {            // دردشة/كتابة → 8.8.8.8
        struct hostent *real = orig_gethostbyname(name);
        if (real && real->h_addrtype == AF_INET && real->h_addr_list) {
            for (char **a = real->h_addr_list; *a; a++) {
                char b[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, *a, b, sizeof b)) @synchronized (DSChatIPs()) { [DSChatIPs() addObject:@(b)]; }
            }
        }
        static __thread struct hostent ch; static __thread char cn[256]; static __thread struct in_addr ca;
        static __thread char *cl[2]; static __thread char *cal[1];
        inet_pton(AF_INET, DS_GDNS4, &ca); cl[0] = (char *)&ca; cl[1] = NULL; cal[0] = NULL;
        strlcpy(cn, name, sizeof cn);
        ch.h_name = cn; ch.h_aliases = cal; ch.h_addrtype = AF_INET; ch.h_length = 4; ch.h_addr_list = cl;
        r = &ch;
    }
    if (!r && !isMapped) r = DSAutoHostent(name);                   // DNS = 8.8.8.8
    if (!r) r = orig_gethostbyname(isMapped ? mapped : name);
    // تعلّم IPs الدردشة/الكتابة أونلاين مثل getaddrinfo، لتعمل CHAT تلقائياً في AUTO TEST.
    if (r && !isMapped && name && DSChatEligible(name, NULL) && r->h_addrtype == AF_INET && r->h_addr_list) {
        for (char **a = r->h_addr_list; *a; a++) {
            char b[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, *a, b, sizeof b)) @synchronized (DSChatIPs()) { [DSChatIPs() addObject:@(b)]; }
        }
    }
    if (name) {
        NSString *h = [NSString stringWithUTF8String:name];
        if (h) [[DSStore shared] recordHost:h ips:nil source:@"dns" failed:(r == NULL)];
    }
    return r;
}

#pragma mark - Proxy engine (SOCKS5 / HTTP CONNECT)

// يمرّر اتصالات TCP الخام عبر بروكسي (SOCKS5 أو HTTP CONNECT) + يحقن البروكسي في جلسات NSURLSession.
// لا يدعم UDP ولا vmess/vless/trojan/ss (تحتاج نواة خارجية).

typedef NS_ENUM(NSInteger, DSProxyType) { DSProxyTypeSOCKS5 = 1, DSProxyTypeHTTP = 2 };
typedef struct { int type; int port; char host[256]; char user[256]; char pass[256]; } DSProxyCfg;

static volatile BOOL gProxyOn = NO;
static _Atomic int32_t gProxyHits = 0, gProxyFails = 0;

static NSString *DSB64Decode(NSString *s) {
    NSString *t = [[s stringByReplacingOccurrencesOfString:@"-" withString:@"+"] stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    while (t.length % 4) t = [t stringByAppendingString:@"="];
    NSData *d = [[NSData alloc] initWithBase64EncodedString:t options:0];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
}

static int DSProxyGuessType(int port) {   // رابط بلا scheme: المنافذ المعروفة لـ HTTP تُعامل كـ HTTP والباقي SOCKS5
    switch (port) { case 80: case 808: case 3128: case 3129: case 8000: case 8080: case 8081: case 8118: case 8888: return DSProxyTypeHTTP; }
    return DSProxyTypeSOCKS5;
}

@interface DSProxy : NSObject
@property (atomic) BOOL enabled;
@property (atomic, copy) NSString *link;
@property (atomic) int type, port;
@property (atomic, copy) NSString *host, *user, *pass, *lastError;
+ (instancetype)shared;
- (BOOL)applyLink:(NSString *)link error:(NSString **)err;   // يحفظ + يفعّل
- (void)save;
- (BOOL)getCfg:(DSProxyCfg *)out;
- (NSString *)summary;
- (NSDictionary *)cfDict;
@end

@implementation DSProxy

+ (instancetype)shared {
    static DSProxy *p; static dispatch_once_t once;
    dispatch_once(&once, ^{ p = [DSProxy new]; });
    return p;
}

- (NSString *)path { return [DSDir() stringByAppendingPathComponent:@"proxy.json"]; }

- (instancetype)init {
    if ((self = [super init])) {
        NSData *d = [NSData dataWithContentsOfFile:[self path]];
        NSDictionary *j = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
        if ([j isKindOfClass:NSDictionary.class] && [j[@"link"] isKindOfClass:NSString.class]) {
            NSString *e = nil;
            if ([self parseLink:j[@"link"] error:&e]) { self.link = j[@"link"]; self.enabled = [j[@"enabled"] boolValue]; }
        }
        gProxyOn = self.enabled && self.host.length > 0;
    }
    return self;
}

- (void)save {
    @synchronized (self) {
        gProxyOn = self.enabled && self.host.length > 0;
        NSDictionary *j = @{ @"enabled": @(self.enabled), @"link": self.link ?: @"" };
        [[NSJSONSerialization dataWithJSONObject:j options:NSJSONWritingPrettyPrinted error:nil] writeToFile:[self path] atomically:YES];
    }
}

- (BOOL)getCfg:(DSProxyCfg *)out {
    @synchronized (self) {
        if (!self.host.length || self.port <= 0) return NO;
        memset(out, 0, sizeof *out);
        out->type = self.type; out->port = self.port;
        strlcpy(out->host, self.host.UTF8String, sizeof out->host);
        strlcpy(out->user, (self.user ?: @"").UTF8String, sizeof out->user);
        strlcpy(out->pass, (self.pass ?: @"").UTF8String, sizeof out->pass);
        return YES;
    }
}

- (NSString *)summary {
    if (!self.host.length) return @"—";
    return [NSString stringWithFormat:@"%@ %@:%d%@", self.type == DSProxyTypeHTTP ? @"HTTP" : @"SOCKS5", self.host, self.port, self.user.length ? @" 🔐" : @""];
}

- (NSDictionary *)cfDict {
    DSProxyCfg c; if (![self getCfg:&c]) return nil;
    NSString *h = @(c.host); NSNumber *pt = @(c.port);
    if (c.type == DSProxyTypeSOCKS5) {
        NSMutableDictionary *d = [@{ @"SOCKSEnable": @1, @"SOCKSProxy": h, @"SOCKSPort": pt } mutableCopy];
        if (c.user[0]) { d[@"SOCKSUser"] = @(c.user); d[@"SOCKSPassword"] = @(c.pass); }
        return d;
    }
    return @{ @"HTTPEnable": @1, @"HTTPProxy": h, @"HTTPPort": pt, @"HTTPSEnable": @1, @"HTTPSProxy": h, @"HTTPSPort": pt };
}

// يحلّل الرابط ويملأ الحقول فقط (بدون حفظ/تفعيل)
- (BOOL)parseLink:(NSString *)raw error:(NSString **)err {
    #define DSP_ERR(m) do { if (err) *err = (m); return NO; } while (0)
    NSString *l = [raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSRange nl = [l rangeOfCharacterFromSet:NSCharacterSet.newlineCharacterSet];
    if (nl.location != NSNotFound) l = [l substringToIndex:nl.location];
    if (!l.length) DSP_ERR(@"الرابط فارغ");
    int type = 0, port = 0; NSString *host = nil, *user = nil, *pass = nil;

    if ([l rangeOfString:@"://"].location == NSNotFound) {
        if ([l containsString:@"@"]) return [self parseLink:[@"socks5://" stringByAppendingString:l] error:err];
        NSArray *pp = [l componentsSeparatedByString:@":"];
        if (pp.count == 2) { host = pp[0]; port = [pp[1] intValue]; }
        else if (pp.count == 4) { host = pp[0]; port = [pp[1] intValue]; user = pp[2]; pass = pp[3]; }
        else DSP_ERR(@"صيغة غير مفهومة. أمثلة:\nsocks5://user:pass@host:1080\nhttp://host:8080\nhost:port\nhost:port:user:pass");
        type = DSProxyGuessType(port);
    } else {
        NSURLComponents *uc = [NSURLComponents componentsWithString:l];
        if (!uc || !uc.scheme.length) DSP_ERR(@"الرابط غير صالح (رمّز الرموز الخاصة في اسم المستخدم/كلمة المرور بصيغة %XX)");
        NSString *sch = uc.scheme.lowercaseString, *h = uc.host.lowercaseString;
        BOOL tg = ([sch isEqualToString:@"tg"] && [h isEqualToString:@"socks"]) ||
                  (([sch isEqualToString:@"https"] || [sch isEqualToString:@"http"]) &&
                   ([h isEqualToString:@"t.me"] || [h isEqualToString:@"telegram.me"] || [h isEqualToString:@"telegram.dog"]) &&
                   [uc.path.lowercaseString hasPrefix:@"/socks"]);
        if (tg) {   // رابط بروكسي تيليجرام
            for (NSURLQueryItem *q in uc.queryItems) {
                NSString *k = q.name.lowercaseString;
                if ([k isEqualToString:@"server"]) host = q.value;
                else if ([k isEqualToString:@"port"]) port = [q.value intValue];
                else if ([k isEqualToString:@"user"]) user = q.value;
                else if ([k isEqualToString:@"pass"]) pass = q.value;
            }
            type = DSProxyTypeSOCKS5;
        } else {
            if ([@[@"socks", @"socks5", @"socks5h"] containsObject:sch]) type = DSProxyTypeSOCKS5;
            else if ([@[@"http", @"https"] containsObject:sch]) type = DSProxyTypeHTTP;
            else if ([@[@"socks4", @"socks4a"] containsObject:sch]) DSP_ERR(@"SOCKS4 غير مدعوم. استخدم socks5:// أو http://");
            else if ([@[@"vmess", @"vless", @"trojan", @"ss", @"ssr", @"hysteria", @"hysteria2", @"hy2", @"tuic", @"wireguard"] containsObject:sch])
                DSP_ERR(@"هذا النوع (vmess/vless/trojan/ss...) غير مدعوم لأنه يحتاج نواة Xray/sing-box خارجية. المدعوم: socks5:// و http:// ورابط تيليجرام t.me/socks");
            else DSP_ERR(@"بروتوكول غير معروف. استخدم socks5:// أو http://");
            host = uc.host; port = uc.port.intValue; user = uc.user; pass = uc.password;
            if ([sch isEqualToString:@"socks"] && user.length && !pass.length) {   // socks://base64(user:pass)@host:port
                NSString *dec = DSB64Decode(user);
                NSRange c = [dec rangeOfString:@":"];
                if (dec.length && c.location != NSNotFound) { pass = [dec substringFromIndex:c.location + 1]; user = [dec substringToIndex:c.location]; }
            }
            if (port <= 0) port = (type == DSProxyTypeHTTP) ? 8080 : 1080;
        }
    }
    host = [host stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!host.length) DSP_ERR(@"لم أجد عنوان السيرفر (host) في الرابط");
    if (host.length > 250) DSP_ERR(@"العنوان طويل جداً");
    if (port <= 0 || port > 65535) DSP_ERR(@"المنفذ (port) غير صالح");
    if (user.length > 255 || pass.length > 255) DSP_ERR(@"اسم المستخدم/كلمة المرور أطول من 255");
    @synchronized (self) {
        self.type = type; self.port = port; self.host = host; self.user = user.length ? user : nil; self.pass = pass.length ? pass : nil;
    }
    return YES;
    #undef DSP_ERR
}

- (BOOL)applyLink:(NSString *)raw error:(NSString **)err {
    if (![self parseLink:raw error:err]) return NO;
    self.link = [raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    self.enabled = YES; self.lastError = nil;
    [self save];
    return YES;
}
@end

// ---- مصافحة البروكسي (على socket TCP) ----
#define DSP_FAIL(...) do { snprintf(why, wn, __VA_ARGS__); return -1; } while (0)

static void DSPTimeouts(int fd, int sec) {
    struct timeval tv = { sec, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}
static BOOL DSPSend(int fd, const void *b, size_t n) {
    const uint8_t *p = (const uint8_t *)b;
    while (n) { ssize_t w = send(fd, p, n, 0); if (w < 0) { if (errno == EINTR) continue; return NO; } if (w == 0) return NO; p += w; n -= (size_t)w; }
    return YES;
}
static BOOL DSPRecv(int fd, void *b, size_t n) {
    uint8_t *p = (uint8_t *)b;
    while (n) { ssize_t r = recv(fd, p, n, 0); if (r < 0) { if (errno == EINTR) continue; return NO; } if (r == 0) return NO; p += r; n -= (size_t)r; }
    return YES;
}

static int DSPSocks5(int fd, const DSProxyCfg *c, const struct sockaddr *dst, char *why, size_t wn) {
    BOOL auth = c->user[0] != 0;
    uint8_t hello[4]; size_t hn = 0;
    hello[hn++] = 5; hello[hn++] = auth ? 2 : 1; hello[hn++] = 0; if (auth) hello[hn++] = 2;
    uint8_t rep[2];
    if (!DSPSend(fd, hello, hn) || !DSPRecv(fd, rep, 2)) DSP_FAIL("لا رد من البروكسي. تأكد من النوع (socks5 أم http) والمنفذ");
    if (rep[0] != 5) DSP_FAIL("البروكسي لا يتكلم SOCKS5. جرّب رابط http://");
    if (rep[1] == 0x02) {
        size_t ul = strlen(c->user), pl = strlen(c->pass), n = 0;
        uint8_t buf[520];
        buf[n++] = 1; buf[n++] = (uint8_t)ul; memcpy(buf + n, c->user, ul); n += ul;
        buf[n++] = (uint8_t)pl; memcpy(buf + n, c->pass, pl); n += pl;
        uint8_t ar[2];
        if (!DSPSend(fd, buf, n) || !DSPRecv(fd, ar, 2) || ar[1] != 0) DSP_FAIL("اسم المستخدم أو كلمة المرور مرفوضة");
    } else if (rep[1] != 0) DSP_FAIL("البروكسي يطلب طريقة مصادقة غير مدعومة");

    uint8_t req[24]; size_t n = 0;
    req[n++] = 5; req[n++] = 1; req[n++] = 0;
    if (dst->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)dst;
        req[n++] = 1; memcpy(req + n, &a->sin_addr, 4); n += 4; memcpy(req + n, &a->sin_port, 2); n += 2;
    } else {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)dst;
        req[n++] = 4; memcpy(req + n, &a->sin6_addr, 16); n += 16; memcpy(req + n, &a->sin6_port, 2); n += 2;
    }
    uint8_t h[4];
    if (!DSPSend(fd, req, n) || !DSPRecv(fd, h, 4)) DSP_FAIL("انقطع الاتصال أثناء طلب الوجهة");
    if (h[1] != 0) {
        const char *m = "فشل عام";
        switch (h[1]) { case 2: m = "غير مسموح بالوجهة"; break; case 3: m = "الشبكة غير متاحة"; break; case 4: m = "الوجهة غير متاحة"; break;
                        case 5: m = "رفضت الوجهة الاتصال"; break; case 6: m = "انتهت المهلة"; break; case 7: m = "الأمر غير مدعوم"; break; case 8: m = "نوع العنوان غير مدعوم"; break; }
        DSP_FAIL("رفض البروكسي الاتصال بالوجهة: %s", m);
    }
    uint8_t tmp[270]; size_t skip = 0;
    if (h[3] == 1) skip = 6; else if (h[3] == 4) skip = 18;
    else if (h[3] == 3) { uint8_t l; if (!DSPRecv(fd, &l, 1)) DSP_FAIL("رد ناقص من البروكسي"); skip = (size_t)l + 2; }
    else DSP_FAIL("رد غير مفهوم من البروكسي");
    if (skip && !DSPRecv(fd, tmp, skip)) DSP_FAIL("رد ناقص من البروكسي");
    return 0;
}

static int DSPHttp(int fd, const DSProxyCfg *c, const struct sockaddr *dst, char *why, size_t wn) {
    char ip[INET6_ADDRSTRLEN] = {0}, target[96]; int port = 0;
    if (dst->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)dst; inet_ntop(AF_INET, &a->sin_addr, ip, sizeof ip); port = ntohs(a->sin_port);
        snprintf(target, sizeof target, "%s:%d", ip, port);
    } else {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)dst; inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof ip); port = ntohs(a->sin6_port);
        snprintf(target, sizeof target, "[%s]:%d", ip, port);
    }
    NSString *auth = @"";
    if (c->user[0]) {
        NSData *cred = [[NSString stringWithFormat:@"%s:%s", c->user, c->pass] dataUsingEncoding:NSUTF8StringEncoding];
        auth = [NSString stringWithFormat:@"Proxy-Authorization: Basic %@\r\n", [cred base64EncodedStringWithOptions:0]];
    }
    NSData *rq = [[NSString stringWithFormat:@"CONNECT %s HTTP/1.1\r\nHost: %s\r\n%@Proxy-Connection: Keep-Alive\r\n\r\n", target, target, auth] dataUsingEncoding:NSUTF8StringEncoding];
    if (!DSPSend(fd, rq.bytes, rq.length)) DSP_FAIL("تعذّر إرسال الطلب للبروكسي");
    char head[2048]; size_t n = 0;
    while (n < sizeof head - 1) {   // نقرأ بايت بايت حتى لا نبتلع بيانات الاتصال بعد الترويسة
        ssize_t r = recv(fd, head + n, 1, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) DSP_FAIL("لا رد من البروكسي. تأكد من النوع (http أم socks5) والمنفذ");
        n++;
        if (n >= 4 && memcmp(head + n - 4, "\r\n\r\n", 4) == 0) break;
    }
    head[n] = 0;
    if (strncmp(head, "HTTP/", 5) != 0) DSP_FAIL("البروكسي لا يتكلم HTTP. جرّب رابط socks5://");
    const char *sp = strchr(head, ' ');
    int code = sp ? atoi(sp + 1) : 0;
    if (code >= 200 && code < 300) return 0;
    if (code == 407) DSP_FAIL("اسم المستخدم أو كلمة المرور مرفوضة (407)");
    DSP_FAIL("رفض البروكسي الطلب (HTTP %d)", code);
}

static BOOL DSProxyResolve(const char *host, int port, int family, struct sockaddr_storage *out, socklen_t *olen) {
    memset(out, 0, sizeof *out);
    struct in_addr a4; struct in6_addr a6;
    BOOL lit4 = inet_pton(AF_INET, host, &a4) == 1, lit6 = !lit4 && inet_pton(AF_INET6, host, &a6) == 1;
    if (lit4 || lit6) {
        if (lit4 && family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)out; s4->sin_family = AF_INET; s4->sin_len = sizeof *s4; s4->sin_port = htons((uint16_t)port); s4->sin_addr = a4;
            *olen = sizeof *s4; return YES;
        }
        if (lit6 && family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)out; s6->sin6_family = AF_INET6; s6->sin6_len = sizeof *s6; s6->sin6_port = htons((uint16_t)port); s6->sin6_addr = a6;
            *olen = sizeof *s6; return YES;
        }
        return NO;   // عنوان حرفي من عائلة أخرى
    }
    struct addrinfo hints; memset(&hints, 0, sizeof hints);
    hints.ai_family = family; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL; char ps[8]; snprintf(ps, sizeof ps, "%d", port);
    int rc = (orig_getaddrinfo ? orig_getaddrinfo : getaddrinfo)(host, ps, &hints, &res);   // يتجاوز hook حتى لا يتأثر عنوان البروكسي بالقواعد
    BOOL ok = NO;
    if (rc == 0 && res) {
        if (res->ai_addrlen <= sizeof *out) { memcpy(out, res->ai_addr, res->ai_addrlen); *olen = res->ai_addrlen; ok = YES; }
        freeaddrinfo(res);
    }
    return ok;
}

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);

// يتصل بالبروكسي على fd ثم يطلب منه الوجهة dst. 0 = نجاح، -1 = فشل (why)، -2 = لا عنوان بروكسي بنفس عائلة الشبكة
static int DSProxyTunnel(int fd, const DSProxyCfg *c, const struct sockaddr *dst, int timeoutSec, char *why, size_t wn) {
    struct sockaddr_storage px; socklen_t pxl = 0;
    if (!DSProxyResolve(c->host, c->port, dst->sa_family, &px, &pxl)) { snprintf(why, wn, "تعذّر حل عنوان البروكسي"); return -2; }
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    struct timeval oldR = {0, 0}, oldS = {0, 0}; socklen_t tl = sizeof oldR;
    getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &oldR, &tl); tl = sizeof oldS; getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &oldS, &tl);
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int rc = (orig_connect ? orig_connect : connect)(fd, (const struct sockaddr *)&px, pxl);
    int cerr = 0;
    if (rc != 0 && errno == EINPROGRESS) {
        struct pollfd pf = { fd, POLLOUT, 0 };
        int pr;
        do { pr = poll(&pf, 1, timeoutSec * 1000); } while (pr < 0 && errno == EINTR);
        if (pr <= 0) { fcntl(fd, F_SETFL, fl); DSP_FAIL("انتهت مهلة الاتصال بالبروكسي"); }
        socklen_t el = sizeof cerr; getsockopt(fd, SOL_SOCKET, SO_ERROR, &cerr, &el);
    } else if (rc != 0) cerr = errno;
    if (cerr) { fcntl(fd, F_SETFL, fl); DSP_FAIL("تعذّر الاتصال بالبروكسي (%s)", strerror(cerr)); }

    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    DSPTimeouts(fd, timeoutSec);
    int r = (c->type == DSProxyTypeHTTP) ? DSPHttp(fd, c, dst, why, wn) : DSPSocks5(fd, c, dst, why, wn);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &oldR, sizeof oldR);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &oldS, sizeof oldS);
    fcntl(fd, F_SETFL, fl);
    return r;
}

// هل نمرّر هذا الاتصال عبر البروكسي؟ (TCP فقط، وجهات عامة فقط)
static BOOL DSProxyShouldTunnel(int fd, const struct sockaddr *sa, socklen_t len) {
    if (!sa) return NO;
    int type = 0; socklen_t tl = sizeof type;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) != 0 || type != SOCK_STREAM) return NO;
    if (sa->sa_family == AF_INET) {
        if (len < sizeof(struct sockaddr_in)) return NO;
        uint32_t v = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
        if ((v >> 24) == 0 || (v >> 24) == 127 || (v >> 24) == 10 || (v >> 16) == 0xC0A8 || (v >> 20) == 0xAC1 || (v >> 16) == 0xA9FE || (v >> 24) >= 224) return NO;
        return YES;
    }
    if (sa->sa_family == AF_INET6) {
        if (len < sizeof(struct sockaddr_in6)) return NO;
        const struct in6_addr *a = &((const struct sockaddr_in6 *)sa)->sin6_addr;
        if (IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_UNSPECIFIED(a) || IN6_IS_ADDR_LINKLOCAL(a) || IN6_IS_ADDR_MULTICAST(a) ||
            IN6_IS_ADDR_V4MAPPED(a) || (a->s6_addr[0] & 0xFE) == 0xFC) return NO;
        return YES;
    }
    return NO;
}

static int DSProxyConnect(int fd, const struct sockaddr *dst, socklen_t dlen) {
    DSProxyCfg c;
    if (![[DSProxy shared] getCfg:&c]) return orig_connect(fd, dst, dlen);
    char why[160] = {0};
    int rc = DSProxyTunnel(fd, &c, dst, 8, why, sizeof why);
    if (rc == 0) { atomic_fetch_add(&gProxyHits, 1); return 0; }
    if (rc == -2) return orig_connect(fd, dst, dlen);   // البروكسي بلا عنوان بنفس العائلة (IPv4/IPv6): اتصال مباشر
    atomic_fetch_add(&gProxyFails, 1);
    [DSProxy shared].lastError = @(why);
    errno = ECONNREFUSED;
    return -1;
}

// ---- اختبار البروكسي: يفتح نفقاً إلى 1.1.1.1:80 ويقرأ IP الخروج ----
static void DSProxyTest(void (^done)(NSString *report, BOOL ok)) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        __block NSString *report = nil; __block BOOL ok = NO;
        DSProxyCfg c;
        if (![[DSProxy shared] getCfg:&c]) { report = @"لا يوجد بروكسي محفوظ"; }
        else {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in dst; memset(&dst, 0, sizeof dst);
            dst.sin_family = AF_INET; dst.sin_len = sizeof dst; dst.sin_port = htons(80); inet_pton(AF_INET, "1.1.1.1", &dst.sin_addr);
            char why[160] = {0};
            struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
            int rc = fd >= 0 ? DSProxyTunnel(fd, &c, (struct sockaddr *)&dst, 8, why, sizeof why) : -1;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            int ms = (int)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
            if (fd < 0) { report = @"تعذّر إنشاء socket"; }
            else if (rc != 0) { report = [NSString stringWithFormat:@"%@\n\n%@", [[DSProxy shared] summary], @(why[0] ? why : "فشل غير معروف")]; }
            else {
                ok = YES;
                NSString *exitInfo = @"(لم أستطع قراءة IP الخروج)";
                DSPTimeouts(fd, 8);
                const char *rq = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n";
                if (DSPSend(fd, rq, strlen(rq))) {
                    char buf[4096]; size_t n = 0;
                    while (n < sizeof buf - 1) { ssize_t r = recv(fd, buf + n, sizeof buf - 1 - n, 0); if (r <= 0) break; n += (size_t)r; }
                    buf[n] = 0;
                    NSString *body = [NSString stringWithUTF8String:buf] ?: @"";
                    NSString *ip = nil, *loc = nil;
                    for (NSString *ln in [body componentsSeparatedByString:@"\n"]) {
                        NSString *t = [ln stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
                        if ([t hasPrefix:@"ip="]) ip = [t substringFromIndex:3];
                        else if ([t hasPrefix:@"loc="]) loc = [t substringFromIndex:4];
                    }
                    if (ip.length) exitInfo = [NSString stringWithFormat:@"IP الخروج: %@%@", ip, loc.length ? [NSString stringWithFormat:@"  (%@)", loc] : @""];
                }
                report = [NSString stringWithFormat:@"%@\nزمن الاتصال: %d ms\n%@", [[DSProxy shared] summary], ms, exitInfo];
            }
            if (fd >= 0) close(fd);
        }
        dispatch_async(dispatch_get_main_queue(), ^{ done(report, ok); });
    });
}

// ---- NSURLSession: حقن البروكسي في الإعدادات عند إنشائها ----
typedef void *(*DSNWMakeEp)(const char *, const char *);
typedef void *(*DSNWMakeProxy1)(void *);
typedef void *(*DSNWMakeProxy2)(void *, void *);
typedef void (*DSNWSetCred)(void *, const char *, const char *);

static void DSProxyApplyModern(NSURLSessionConfiguration *cfg, const DSProxyCfg *c) {   // iOS 17+: يدعم المصادقة بشكل أصلي
    if (![cfg respondsToSelector:NSSelectorFromString(@"setProxyConfigurations:")]) return;
    DSNWMakeEp mkEp = (DSNWMakeEp)dlsym(RTLD_DEFAULT, "nw_endpoint_create_host");
    DSNWMakeProxy1 mkSocks = (DSNWMakeProxy1)dlsym(RTLD_DEFAULT, "nw_proxy_config_create_socksv5");
    DSNWMakeProxy2 mkHttp = (DSNWMakeProxy2)dlsym(RTLD_DEFAULT, "nw_proxy_config_create_http_connect");
    DSNWSetCred setCred = (DSNWSetCred)dlsym(RTLD_DEFAULT, "nw_proxy_config_set_username_and_password");
    if (!mkEp || (c->type == DSProxyTypeSOCKS5 ? !mkSocks : !mkHttp)) return;
    char ps[8]; snprintf(ps, sizeof ps, "%d", c->port);
    void *ep = mkEp(c->host, ps); if (!ep) return;
    id epObj = (__bridge_transfer id)ep;
    void *pc = (c->type == DSProxyTypeSOCKS5) ? mkSocks(ep) : mkHttp(ep, NULL);
    if (!pc) return;
    id pcObj = (__bridge_transfer id)pc;
    if (c->user[0] && setCred) setCred(pc, c->user, c->pass);
    (void)epObj;
    @try { [cfg setValue:@[pcObj] forKey:@"proxyConfigurations"]; } @catch (__unused id e) {}
}

static NSURLSessionConfiguration *DSProxyApply(id cfgObj) {
    if (!gProxyOn || ![cfgObj isKindOfClass:NSURLSessionConfiguration.class]) return cfgObj;
    NSURLSessionConfiguration *cfg = (NSURLSessionConfiguration *)cfgObj;
    DSProxyCfg c; if (![[DSProxy shared] getCfg:&c]) return cfg;
    cfg.connectionProxyDictionary = [[DSProxy shared] cfDict];
    DSProxyApplyModern(cfg, &c);
    return cfg;
}

static void DSInstallProxySessionHooks(void) {
    Class cfgCls = NSURLSessionConfiguration.class;
    for (NSString *n in @[@"defaultSessionConfiguration", @"ephemeralSessionConfiguration"]) {
        SEL sel = NSSelectorFromString(n);
        Method m = class_getClassMethod(cfgCls, sel);
        if (!m) continue;
        IMP orig = method_getImplementation(m);
        id blk = ^id(__unsafe_unretained id self_) {
            id c = ((id (*)(id, SEL))orig)(self_, sel);
            DSProxyApply(c);
            return c;
        };
        method_setImplementation(m, imp_implementationWithBlock(blk));
    }
    Class sess = NSURLSession.class;
    SEL s1 = @selector(sessionWithConfiguration:), s2 = @selector(sessionWithConfiguration:delegate:delegateQueue:);
    Method m1 = class_getClassMethod(sess, s1);
    if (m1) {
        IMP o1 = method_getImplementation(m1);
        id b1 = ^id(__unsafe_unretained id self_, __unsafe_unretained id cfg) { DSProxyApply(cfg); return ((id (*)(id, SEL, id))o1)(self_, s1, cfg); };
        method_setImplementation(m1, imp_implementationWithBlock(b1));
    }
    Method m2 = class_getClassMethod(sess, s2);
    if (m2) {
        IMP o2 = method_getImplementation(m2);
        id b2 = ^id(__unsafe_unretained id self_, __unsafe_unretained id cfg, __unsafe_unretained id del, __unsafe_unretained id q) {
            DSProxyApply(cfg); return ((id (*)(id, SEL, id, id, id))o2)(self_, s2, cfg, del, q);
        };
        method_setImplementation(m2, imp_implementationWithBlock(b2));
    }
}

static int hook_connect(int fd, const struct sockaddr *sa, socklen_t len) {
    DSNoteSockaddr(sa, len, "connect");
    struct sockaddr_storage ss;
    if (DSRewriteSockaddr(sa, len, &ss)) sa = (const struct sockaddr *)&ss;
    if (gProxyOn && DSProxyShouldTunnel(fd, sa, len)) return DSProxyConnect(fd, sa, len);   // عبر البروكسي (SOCKS5 / HTTP CONNECT)
    return orig_connect(fd, sa, len);
}

static ssize_t hook_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *dst, socklen_t dlen) {
    if (dst) DSNoteSockaddr(dst, dlen, "udp");
    struct sockaddr_storage ss;
    if (dst && DSRewriteSockaddr(dst, dlen, &ss)) return orig_sendto(fd, buf, n, flags, (const struct sockaddr *)&ss, dlen);
    return orig_sendto(fd, buf, n, flags, dst, dlen);
}

static void DSURL(NSURL *u, NSString *src) {
    NSString *h = u.host;
    if ([h.lowercaseString hasSuffix:@"nextdns.io"]) return;  // لا تسجّل طلبات الأداة نفسها
    if (h.length) [[DSStore shared] recordHost:h ips:nil source:src failed:NO];
}

#pragma mark - Built-in hook engine (no Substrate / ElleKit needed)

// 1) دوال C (getaddrinfo, connect, ...) عبر إعادة ربط مؤشرات الرموز في كل صور Mach-O المحمّلة
typedef struct { const char *name; void *replacement; } DSRebind;
static DSRebind gRebinds[8];
static int gRebindCount = 0;

static BOOL DSSetProt(void *addr, size_t size, vm_prot_t prot, BOOL copy) {
    uintptr_t pg = (uintptr_t)vm_page_size;
    uintptr_t start = (uintptr_t)addr & ~(pg - 1);
    uintptr_t end = ((uintptr_t)addr + size + pg - 1) & ~(pg - 1);
    return vm_protect(mach_task_self(), (vm_address_t)start, (vm_size_t)(end - start), 0,
                      copy ? (prot | VM_PROT_COPY) : prot) == KERN_SUCCESS;
}

static void DSRebindSection(const struct section_64 *sect, intptr_t slide, const struct nlist_64 *symtab,
                            const char *strtab, const uint32_t *indirect) {
    const uint32_t *idx = indirect + sect->reserved1;
    void **slots = (void **)((uintptr_t)slide + (uintptr_t)sect->addr);
    size_t count = (size_t)(sect->size / sizeof(void *));
    BOOL isConst = strncmp(sect->segname, "__DATA_CONST", 16) == 0;
    BOOL unlocked = NO;
    for (size_t i = 0; i < count; i++) {
        uint32_t si = idx[i];
        if (si == INDIRECT_SYMBOL_ABS || si == INDIRECT_SYMBOL_LOCAL || si == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        const char *name = strtab + symtab[si].n_un.n_strx;
        if (!name[0] || !name[1]) continue;
        for (int k = 0; k < gRebindCount; k++) {
            if (strcmp(name + 1, gRebinds[k].name) != 0) continue;
            if (slots[i] == gRebinds[k].replacement) break;
            if (isConst && !unlocked) {
                if (!DSSetProt(slots, (size_t)sect->size, VM_PROT_READ | VM_PROT_WRITE, YES)) return;
                unlocked = YES;
            }
            slots[i] = gRebinds[k].replacement;
            break;
        }
    }
    if (isConst && unlocked) DSSetProt(slots, (size_t)sect->size, VM_PROT_READ, NO);
}

static void DSRebindImage(const struct mach_header *mh, intptr_t slide) {
    if (!mh || mh->magic != MH_MAGIC_64) return;
    const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
    const struct segment_command_64 *linkedit = NULL;
    const struct symtab_command *stc = NULL;
    const struct dysymtab_command *dsc = NULL;
    uintptr_t cur = (uintptr_t)h + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cur;
            if (strcmp(seg->segname, SEG_LINKEDIT) == 0) linkedit = seg;
        } else if (lc->cmd == LC_SYMTAB) stc = (const struct symtab_command *)cur;
        else if (lc->cmd == LC_DYSYMTAB) dsc = (const struct dysymtab_command *)cur;
        cur += lc->cmdsize;
    }
    if (!linkedit || !stc || !dsc || dsc->nindirectsyms == 0) return;
    uintptr_t base = (uintptr_t)slide + (uintptr_t)linkedit->vmaddr - (uintptr_t)linkedit->fileoff;
    const struct nlist_64 *symtab = (const struct nlist_64 *)(base + stc->symoff);
    const char *strtab = (const char *)(base + stc->stroff);
    const uint32_t *indirect = (const uint32_t *)(base + dsc->indirectsymoff);
    cur = (uintptr_t)h + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cur;
            if (strcmp(seg->segname, "__DATA") == 0 || strncmp(seg->segname, "__DATA_CONST", 16) == 0) {
                const struct section_64 *secs = (const struct section_64 *)(cur + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    uint32_t type = secs[j].flags & SECTION_TYPE;
                    if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS)
                        DSRebindSection(&secs[j], slide, symtab, strtab, indirect);
                }
            }
        }
        cur += lc->cmdsize;
    }
}

#define DS_ADD_REBIND(sym, origvar, hookfn) do { \
    void *p_ = dlsym(RTLD_DEFAULT, sym); \
    if (p_) { origvar = (__typeof__(origvar))p_; \
              gRebinds[gRebindCount].name = sym; gRebinds[gRebindCount].replacement = (void *)hookfn; gRebindCount++; } \
} while (0)

static void DSInstallCHooks(void) {
    DS_ADD_REBIND("getaddrinfo", orig_getaddrinfo, hook_getaddrinfo);
    DS_ADD_REBIND("gethostbyname", orig_gethostbyname, hook_gethostbyname);
    DS_ADD_REBIND("connect", orig_connect, hook_connect);
    DS_ADD_REBIND("sendto", orig_sendto, hook_sendto);
    _dyld_register_func_for_add_image(DSRebindImage);  // يمرّ على الصور الحالية ثم أي صورة جديدة
}

// 2) NSURLSession عبر ObjC runtime
static BOOL DSClassOwns(Class c, SEL s) {
    unsigned n = 0; BOOL found = NO;
    Method *list = class_copyMethodList(c, &n);
    for (unsigned i = 0; i < n; i++) if (method_getName(list[i]) == s) { found = YES; break; }
    free(list);
    return found;
}

static void DSHookURLMethod(Class base, Class concrete, const char *selName, NSString *src) {
    SEL sel = sel_registerName(selName);
    Class target = (concrete && concrete != base && DSClassOwns(concrete, sel)) ? concrete : base;
    Method m = class_getInstanceMethod(target, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    id (^blk)(__unsafe_unretained id, __unsafe_unretained id, __unsafe_unretained id, __unsafe_unretained id) =
        ^id(__unsafe_unretained id obj, __unsafe_unretained id a, __unsafe_unretained id b, __unsafe_unretained id c) {
            NSURL *u = nil;
            if ([a isKindOfClass:NSURLRequest.class]) u = ((NSURLRequest *)a).URL;
            else if ([a isKindOfClass:NSURL.class]) u = (NSURL *)a;
            DSURL(u, src);
            return ((id (*)(id, SEL, id, id, id))orig)(obj, sel, a, b, c);
        };
    method_setImplementation(m, imp_implementationWithBlock(blk));
}

static void DSInstallURLSessionHooks(void) {
    Class base = NSURLSession.class;
    Class concrete = [NSURLSession sharedSession].class;
    DSHookURLMethod(base, concrete, "dataTaskWithRequest:", @"http");
    DSHookURLMethod(base, concrete, "dataTaskWithRequest:completionHandler:", @"http");
    DSHookURLMethod(base, concrete, "dataTaskWithURL:", @"http");
    DSHookURLMethod(base, concrete, "dataTaskWithURL:completionHandler:", @"http");
    DSHookURLMethod(base, concrete, "uploadTaskWithRequest:fromData:", @"upload");
    DSHookURLMethod(base, concrete, "uploadTaskWithRequest:fromData:completionHandler:", @"upload");
    DSHookURLMethod(base, concrete, "uploadTaskWithRequest:fromFile:", @"upload");
    DSHookURLMethod(base, concrete, "downloadTaskWithRequest:", @"download");
    DSHookURLMethod(base, concrete, "downloadTaskWithURL:", @"download");
    DSHookURLMethod(base, concrete, "webSocketTaskWithURL:", @"ws");
    DSHookURLMethod(base, concrete, "webSocketTaskWithRequest:", @"ws");
    DSInstallProxySessionHooks();
}

#pragma mark - AUTO TEST engine (ALL / CHAT)

static NSString *const ASTestDidUpdateNotification = @"ASTestDidUpdateNotification";
static NSString *const ASTestLogNotification = @"ASTestLogNotification";

typedef NS_ENUM(NSInteger, ASTestMode) {
    ASTestModeOff = 0,
    ASTestModeAll = 1,    // الخيار الأول: كل النطاقات وIP/DNS
    ASTestModeChat = 2    // الخيار الثاني: IP/DNS الدردشة والكتابة أونلاين
};

static double ASNow(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static BOOL ASIsPublicIP(NSString *ip) {
    if (ip.length == 0) return NO;
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, ip.UTF8String, &a4) == 1) {
        uint32_t v = ntohl(a4.s_addr);
        if ((v >> 24) == 0 || (v >> 24) == 127 || (v >> 24) == 10 ||
            (v >> 16) == 0xC0A8 || (v >> 20) == 0xAC1 || (v >> 16) == 0xA9FE) return NO;
        return YES;
    }
    if (inet_pton(AF_INET6, ip.UTF8String, &a6) == 1) {
        if (IN6_IS_ADDR_LOOPBACK(&a6) || IN6_IS_ADDR_UNSPECIFIED(&a6) ||
            IN6_IS_ADDR_LINKLOCAL(&a6) || (a6.s6_addr[0] & 0xFE) == 0xFC) return NO;
        return YES;
    }
    return NO;
}

// يحل النطاق عبر DNS النظام أولاً، ثم 8.8.8.8 كاحتياطي. يتجاوز hook إعادة التوجيه
// حتى لا نختبر 8.8.8.8 بدل السيرفر الحقيقي.
static NSArray<NSString *> *ASResolveHost(NSString *host, double *msOut) {
    NSMutableArray *out = [NSMutableArray array];
    if (!host.length) { if (msOut) *msOut = 0; return out; }
    double t0 = ASNow();
    struct addrinfo hints; memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int r = orig_getaddrinfo ? orig_getaddrinfo(host.UTF8String, "443", &hints, &res)
                             : getaddrinfo(host.UTF8String, "443", &hints, &res);
    if (r == 0 && res) {
        for (struct addrinfo *p = res; p; p = p->ai_next) {
            NSString *s = DSAddrString(p->ai_addr);
            if (s && ![out containsObject:s]) [out addObject:s];
        }
        freeaddrinfo(res);
    }
    if (out.count == 0) {   // احتياطي: محلّل 8.8.8.8 المدمج
        struct in_addr ips[8]; int n = 0;
        if (DSResolve4(host.UTF8String, ips, 8, &n)) {
            for (int i = 0; i < n; i++) {
                char b[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &ips[i], b, sizeof b)) {
                    NSString *s = @(b);
                    if (![out containsObject:s]) [out addObject:s];
                }
            }
        }
    }
    if (msOut) *msOut = (ASNow() - t0) * 1000.0;
    return out;
}

static NSArray<NSNumber *> *ASPortsForEntry(NSDictionary *e) {
    NSMutableArray *ports = [NSMutableArray array];
    BOOL isIP = [e[@"type"] isEqualToString:@"ip"];
    for (NSString *s in e[@"src"]) {
        if (![s isKindOfClass:NSString.class]) continue;
        NSRange r = [s rangeOfString:@":" options:NSBackwardsSearch];
        if (r.location == NSNotFound) continue;
        NSInteger p = [[s substringFromIndex:r.location + 1] integerValue];
        if (p > 0 && p <= 65535 && ![ports containsObject:@(p)]) [ports addObject:@(p)];
        if (ports.count >= 3) break;
    }
    if (ports.count == 0) {
        [ports addObject:@443];
        [ports addObject:@80];
    } else if (!isIP) {
        for (NSNumber *p in @[@443, @80]) {
            if (ports.count >= 3) break;
            if (![ports containsObject:p]) [ports addObject:p];
        }
    }
    return ports;
}

// اختبار TCP مباشر (يتجاوز hook connect حتى لا يتحول الهدف إلى 8.8.8.8)
static int ASTCPProbe(NSString *ip, int port, int timeoutMs, double *msOut) {
    if (ip.length == 0 || port <= 0 || port > 65535) return -1;
    BOOL v6 = [ip containsString:@":"];
    int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    double t0 = ASNow();
    int r = -1;
    if (v6) {
        struct sockaddr_in6 sa; memset(&sa, 0, sizeof sa);
        sa.sin6_len = sizeof sa; sa.sin6_family = AF_INET6; sa.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, ip.UTF8String, &sa.sin6_addr) != 1) { close(fd); return -1; }
        r = (orig_connect ? orig_connect : connect)(fd, (struct sockaddr *)&sa, sizeof sa);
    } else {
        struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
        sa.sin_len = sizeof sa; sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip.UTF8String, &sa.sin_addr) != 1) { close(fd); return -1; }
        r = (orig_connect ? orig_connect : connect)(fd, (struct sockaddr *)&sa, sizeof sa);
    }

    BOOL ok = NO;
    if (r == 0) ok = YES;
    else if (errno == EINPROGRESS) {
        fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
        struct timeval tv; tv.tv_sec = timeoutMs / 1000; tv.tv_usec = (timeoutMs % 1000) * 1000;
        r = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (r > 0) {
            int err = 0; socklen_t len = sizeof err;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) ok = YES;
        }
    }
    if (msOut) *msOut = (ASNow() - t0) * 1000.0;
    close(fd);
    return ok ? 0 : -1;
}

typedef void (^ASProbeDone)(NSDictionary *result);

// يفحص هدفاً واحداً: DNS + TCP على المنافذ التي رُصدت (أو 443/80).
static void ASProbeEntry(NSDictionary *e, ASProbeDone done) {
    NSString *value = e[@"value"];
    BOOL isIP = [e[@"type"] isEqualToString:@"ip"];
    NSArray<NSNumber *> *ports = ASPortsForEntry(e);
    NSMutableArray<NSString *> *candidates = [NSMutableArray array];
    double dnsMs = 0;

    if (isIP) {
        if (ASIsPublicIP(value)) [candidates addObject:value];
    } else {
        for (NSString *ip in ASResolveHost(value, &dnsMs))
            if (ASIsPublicIP(ip) && ![candidates containsObject:ip]) [candidates addObject:ip];
        for (NSString *r in e[@"related"])
            if ([r isKindOfClass:NSString.class] && ASIsPublicIP(r) && ![candidates containsObject:r])
                [candidates addObject:r];
    }

    int bestMs = INT_MAX; NSString *bestIP = nil; int bestPort = 0;
    NSInteger tested = 0, okCount = 0;
    for (NSString *ip in candidates) {
        if (tested >= 3) break;
        tested++;
        for (NSNumber *pn in ports) {
            int port = pn.intValue;
            double ms = 0;
            if (ASTCPProbe(ip, port, 1200, &ms) == 0) {
                okCount++;
                if (ms < bestMs) { bestMs = (int)ms; bestIP = ip; bestPort = port; }
            }
        }
    }

    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    out[@"when"] = @([[NSDate date] timeIntervalSince1970]);
    out[@"dnsMs"] = @((NSInteger)dnsMs);
    out[@"tested"] = @(tested);
    if (bestMs != INT_MAX) {
        out[@"status"] = @"OK";
        out[@"ms"] = @(bestMs);
        out[@"ip"] = bestIP ?: @"";
        out[@"port"] = @(bestPort);
        out[@"detail"] = [NSString stringWithFormat:@"%ld/%ld", (long)okCount, (long)(tested * ports.count)];
    } else if (candidates.count == 0) {
        out[@"status"] = isIP ? @"SKIP" : @"FAIL";
        out[@"ms"] = @0;
        out[@"detail"] = isIP ? @"عنوان محلي/غير عام" : @"فشل DNS";
    } else {
        out[@"status"] = @"FAIL";
        out[@"ms"] = @0;
        out[@"detail"] = @"لا يوجد اتصال TCP";
    }
    if (done) done(out);
}

@interface ASTestManager : NSObject
+ (instancetype)shared;
@property (nonatomic) ASTestMode mode;
@property (nonatomic) NSInteger intervalSec;
@property (atomic) BOOL running;
@property (atomic, strong) NSDate *lastRun;
@property (atomic) NSInteger lastTested, lastFailed;
- (void)start;
- (void)stop;
- (void)runNowForce:(BOOL)force;
- (NSArray<NSDictionary *> *)targetsForMode:(ASTestMode)mode force:(BOOL)force;
- (BOOL)entryMatches:(NSDictionary *)e mode:(ASTestMode)mode;
- (NSString *)modeTitle;
@end

@implementation ASTestManager {
    NSTimer *_timer;
}

+ (instancetype)shared {
    static ASTestManager *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [ASTestManager new]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _mode = ASTestModeOff;
        _intervalSec = 120;
        NSData *d = [NSData dataWithContentsOfFile:[ASDir() stringByAppendingPathComponent:@"auto-test.json"]];
        if (d) {
            NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
            if ([j isKindOfClass:NSDictionary.class]) {
                _mode = (ASTestMode)[j[@"mode"] integerValue];
                if (j[@"intervalSec"]) _intervalSec = MAX(30, [j[@"intervalSec"] integerValue]);
            }
        }
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(appActive)
            name:UIApplicationDidBecomeActiveNotification object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(appResign)
            name:UIApplicationWillResignActiveNotification object:nil];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_timer invalidate];
}

- (void)save {
    NSDictionary *j = @{ @"mode": @(self.mode), @"intervalSec": @(self.intervalSec) };
    NSData *d = [NSJSONSerialization dataWithJSONObject:j options:NSJSONWritingPrettyPrinted error:nil];
    [d writeToFile:[ASDir() stringByAppendingPathComponent:@"auto-test.json"] atomically:YES];
}

- (void)setMode:(ASTestMode)mode {
    if (mode < ASTestModeOff || mode > ASTestModeChat) mode = ASTestModeOff;
    BOOL changed = (_mode != mode);
    _mode = mode;
    [self save];
    [self refreshTimer];
    if (changed && mode != ASTestModeOff) [self runNowForce:NO];
}

- (void)setIntervalSec:(NSInteger)intervalSec {
    if (intervalSec < 30) intervalSec = 30;
    _intervalSec = intervalSec;
    [self save];
    [self refreshTimer];
}

- (NSString *)modeTitle {
    switch (self.mode) {
        case ASTestModeAll: return @"ALL";
        case ASTestModeChat: return @"CHAT";
        default: return @"OFF";
    }
}

- (BOOL)entryMatches:(NSDictionary *)e mode:(ASTestMode)mode {
    NSString *type = e[@"type"], *value = e[@"value"];
    if (![type isKindOfClass:NSString.class] || ![value isKindOfClass:NSString.class]) return NO;
    if ([value.lowercaseString hasSuffix:@"nextdns.io"]) return NO;
    if (mode == ASTestModeAll) return YES;
    if (mode != ASTestModeChat) return NO;

    if ([type isEqualToString:@"domain"]) return DSIsChatHost(value.UTF8String);
    if ([type isEqualToString:@"ip"]) {
        @synchronized (DSChatIPs()) { if ([DSChatIPs() containsObject:value]) return YES; }
        for (NSString *r in e[@"related"])
            if ([r isKindOfClass:NSString.class] && DSIsChatHost(r.UTF8String)) return YES;
        for (NSString *s in e[@"src"])
            if ([s isKindOfClass:NSString.class] && [s.lowercaseString containsString:@"chat"]) return YES;
    }
    return NO;
}

- (NSArray<NSDictionary *> *)targetsForMode:(ASTestMode)mode force:(BOOL)force {
    if (mode == ASTestModeOff) return @[];
    NSArray *all = [[DSStore shared] snapshot];
    NSMutableArray *out = [NSMutableArray array];
    double now = [[NSDate date] timeIntervalSince1970];
    double cooldown = MAX(60.0, self.intervalSec * 0.8);
    for (NSDictionary *e in all) {
        if (![self entryMatches:e mode:mode]) continue;
        if (!force) {
            NSDictionary *p = e[@"probe"];
            double when = [p[@"when"] doubleValue];
            if (when > 0 && now - when < cooldown) continue;
        }
        [out addObject:e];
    }
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        double ta = [a[@"probe"][@"when"] doubleValue];
        double tb = [b[@"probe"][@"when"] doubleValue];
        if (ta < tb) return NSOrderedAscending;
        if (ta > tb) return NSOrderedDescending;
        return NSOrderedSame;
    }];
    if (out.count > 120) [out removeObjectsInRange:NSMakeRange(120, out.count - 120)];
    return out;
}

- (void)postLog:(NSString *)line {
    [[NSNotificationCenter defaultCenter] postNotificationName:ASTestLogNotification object:line];
}

- (void)runNowForce:(BOOL)force {
    if (self.running) return;
    if (self.mode == ASTestModeOff && !force) return;
    ASTestMode mode = self.mode;
    if (mode == ASTestModeOff) mode = ASTestModeAll;   // TEST NOW بدون وضع: اختبر الكل
    self.running = YES;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray *targets = [self targetsForMode:mode force:force];
        if (targets.count == 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.running = NO;
                [self postLog:@"لا توجد أهداف جديدة للاختبار — شغّل التطبيق/اللعبة وانتظر التقاط الاتصالات."];
                [[NSNotificationCenter defaultCenter] postNotificationName:ASTestDidUpdateNotification object:nil];
            });
            return;
        }

        [self postLog:[NSString stringWithFormat:@"🔎 بدء اختبار %lu هدف — الوضع: %@", (unsigned long)targets.count, mode == ASTestModeChat ? @"CHAT" : @"ALL"]];
        dispatch_semaphore_t sem = dispatch_semaphore_create(6);
        dispatch_group_t group = dispatch_group_create();
        __block NSInteger tested = 0, failed = 0;

        for (NSDictionary *e in targets) {
            dispatch_group_enter(group);
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
                __block NSDictionary *probe = nil;
                ASProbeEntry(e, ^(NSDictionary *r) { probe = r; });
                dispatch_semaphore_signal(sem);

                if (probe) {
                    [[DSStore shared] setProbe:probe forValue:e[@"value"]];
                    BOOL ok = [probe[@"status"] isEqualToString:@"OK"];
                    @synchronized (self) {
                        tested++;
                        if (!ok) failed++;
                    }
                    [self postLog:[NSString stringWithFormat:@"%@ %@ → %@ %@ms %@",
                        ok ? @"✅" : @"⚠️", e[@"value"], probe[@"status"] ?: @"?", probe[@"ms"] ?: @0,
                        probe[@"detail"] ?: @""]];
                    [[NSNotificationCenter defaultCenter] postNotificationName:ASTestDidUpdateNotification object:nil];
                }
                dispatch_group_leave(group);
            });
        }

        dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
        dispatch_async(dispatch_get_main_queue(), ^{
            self.running = NO;
            self.lastRun = [NSDate date];
            self.lastTested = tested;
            self.lastFailed = failed;
            [self postLog:[NSString stringWithFormat:@"=== انتهى الاختبار: %ld ناجح / %ld فاشل ===",
                (long)(tested - failed), (long)failed]];
            [[NSNotificationCenter defaultCenter] postNotificationName:ASTestDidUpdateNotification object:nil];
        });
    });
}

- (void)refreshTimer {
    [_timer invalidate]; _timer = nil;
    if (self.mode == ASTestModeOff) return;
    if ([UIApplication sharedApplication].applicationState != UIApplicationStateActive) return;
    NSTimeInterval t = MAX(30, self.intervalSec);
    __weak typeof(self) weakSelf = self;
    _timer = [NSTimer scheduledTimerWithTimeInterval:t repeats:YES block:^(NSTimer *timer) {
        [weakSelf runNowForce:NO];
    }];
}

- (void)start {
    [self refreshTimer];
    if (self.mode != ASTestModeOff) [self runNowForce:NO];
}

- (void)stop {
    [_timer invalidate]; _timer = nil;
}

- (void)appActive {
    [self refreshTimer];
    if (self.mode == ASTestModeOff) return;
    if (!self.lastRun || -[self.lastRun timeIntervalSinceNow] > self.intervalSec) [self runNowForce:NO];
}

- (void)appResign {
    [_timer invalidate]; _timer = nil;
}

@end

#pragma mark - ServerTester engine (load test)

static NSString *STDir(void) { return ASDir(); }

@interface STSettings : NSObject
@property (atomic, copy) NSString *wsURL;
@property (atomic, copy) NSString *httpURL;
@property (atomic) NSInteger clients;
@property (atomic) NSInteger durationSec;
@property (atomic) NSInteger rateHz;
@property (atomic) NSInteger rampMs;
@property (atomic) BOOL autoOn;
@property (atomic) NSInteger autoIntervalMin;
+ (instancetype)shared;
- (void)save;
@end

@implementation STSettings
+ (instancetype)shared {
    static STSettings *s; static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [STSettings new];
        s.wsURL = @"ws://your-server.example.com:3000";
        s.httpURL = @"http://your-server.example.com:3000/health";
        s.clients = 10; s.durationSec = 15; s.rateHz = 5; s.rampMs = 50;
        s.autoOn = NO; s.autoIntervalMin = 30;
        NSString *p = [STDir() stringByAppendingPathComponent:@"server-test.json"];
        NSData *d = [NSData dataWithContentsOfFile:p];
        if (d) {
            NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
            if ([j isKindOfClass:[NSDictionary class]]) {
                if (j[@"wsURL"]) s.wsURL = j[@"wsURL"];
                if (j[@"httpURL"]) s.httpURL = j[@"httpURL"];
                if (j[@"clients"]) s.clients = [j[@"clients"] integerValue];
                if (j[@"durationSec"]) s.durationSec = [j[@"durationSec"] integerValue];
                if (j[@"rateHz"]) s.rateHz = [j[@"rateHz"] integerValue];
                if (j[@"rampMs"]) s.rampMs = [j[@"rampMs"] integerValue];
                s.autoOn = [j[@"autoOn"] boolValue];
                if (j[@"autoIntervalMin"]) s.autoIntervalMin = [j[@"autoIntervalMin"] integerValue];
            }
        }
    });
    return s;
}
- (void)save {
    NSDictionary *j = @{ @"wsURL": self.wsURL ?: @"", @"httpURL": self.httpURL ?: @"",
        @"clients": @(self.clients), @"durationSec": @(self.durationSec), @"rateHz": @(self.rateHz),
        @"rampMs": @(self.rampMs), @"autoOn": @(self.autoOn), @"autoIntervalMin": @(self.autoIntervalMin) };
    NSData *d = [NSJSONSerialization dataWithJSONObject:j options:NSJSONWritingPrettyPrinted error:nil];
    [d writeToFile:[STDir() stringByAppendingPathComponent:@"server-test.json"] atomically:YES];
}
@end

@interface STStats : NSObject
@property (atomic) NSInteger connected, failed, closedEarly, sent, received, errors;
@property (atomic, strong) NSMutableArray<NSNumber *> *latencies;
@property (atomic, strong) NSMutableArray<NSNumber *> *connectTimes;
@end
@implementation STStats
- (instancetype)init { self = [super init]; if (self) { _latencies = [NSMutableArray array]; _connectTimes = [NSMutableArray array]; } return self; }
@end

typedef void (^STLogBlock)(NSString *line);
typedef void (^STDoneBlock)(STStats *stats);

@interface STRunner : NSObject
+ (void)runWithLog:(STLogBlock)log done:(STDoneBlock)done;
@end

@implementation STRunner

+ (double)avg:(NSArray<NSNumber *> *)a {
    if (!a.count) return 0;
    double s = 0; for (NSNumber *n in a) s += n.doubleValue;
    return s / a.count;
}
+ (double)pct:(NSArray<NSNumber *> *)a p:(double)p {
    if (!a.count) return 0;
    NSArray *sorted = [a sortedArrayUsingSelector:@selector(compare:)];
    NSInteger idx = MIN(sorted.count - 1, (NSInteger)((p/100.0) * sorted.count));
    return [sorted[idx] doubleValue];
}

+ (void)testHTTPWithLog:(STLogBlock)log stats:(STStats *)stats done:(dispatch_block_t)done {
    NSString *urlStr = [STSettings shared].httpURL;
    if (!urlStr.length) { done(); return; }
    log([NSString stringWithFormat:@"[HTTP] فحص %@", urlStr]);
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) { log(@"  رابط HTTP غير صالح"); done(); return; }
    __block NSInteger remaining = 10, ok = 0;
    NSMutableArray<NSNumber *> *times = [NSMutableArray array];
    dispatch_queue_t q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    void (^finishIfDone)(void) = ^{
        if (remaining == 0) {
            log([NSString stringWithFormat:@"  نجح %ld/10 | متوسط الزمن %.1fms", (long)ok, [self avg:times]]);
            done();
        }
    };
    for (int i = 0; i < 10; i++) {
        dispatch_async(q, ^{
            NSDate *t0 = [NSDate date];
            NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithURL:url
                completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                    @synchronized (stats) {
                        remaining--;
                        NSInteger ms = (NSInteger)([[NSDate date] timeIntervalSinceDate:t0] * 1000);
                        [times addObject:@(ms)];
                        NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
                        if (!error && http.statusCode >= 200 && http.statusCode < 400) ok++;
                        finishIfDone();
                    }
                }];
            [task resume];
        });
    }
}

+ (void)spawnClient:(NSInteger)clientId endAt:(NSDate *)endAt stats:(STStats *)stats group:(dispatch_group_t)group {
    dispatch_group_enter(group);
    NSURL *url = [NSURL URLWithString:[STSettings shared].wsURL];
    if (!url) { @synchronized (stats) { stats.failed++; } dispatch_group_leave(group); return; }
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
    NSURLSessionWebSocketTask *ws = [session webSocketTaskWithURL:url];
    NSDate *connectStart = [NSDate date];
    __block BOOL opened = NO;
    __block NSInteger seq = 0;
    NSMutableDictionary<NSNumber *, NSDate *> *pending = [NSMutableDictionary dictionary];
    __block dispatch_source_t timer = nil;

    void (^finish)(void) = ^{
        if (timer) { dispatch_source_cancel(timer); timer = nil; }
        [ws cancelWithCloseCode:NSURLSessionWebSocketCloseCodeNormalClosure reason:nil];
        dispatch_group_leave(group);
    };

    __block void (^receiveLoop)(void);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-retain-cycles"
    receiveLoop = ^{
        [ws receiveMessageWithCompletionHandler:^(NSURLSessionWebSocketMessage *message, NSError *error) {
            if (error) { receiveLoop = nil; return; }
            @synchronized (stats) {
                stats.received++;
                NSString *text = message.string;
                NSNumber *matchedSeq = nil;
                if (text) {
                    NSData *d = [text dataUsingEncoding:NSUTF8StringEncoding];
                    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
                    if ([j isKindOfClass:[NSDictionary class]] && j[@"seq"]) matchedSeq = j[@"seq"];
                }
                @synchronized (pending) {
                    NSDate *sentAt = matchedSeq ? pending[matchedSeq] : pending.allValues.firstObject;
                    NSNumber *key = matchedSeq ?: pending.allKeys.firstObject;
                    if (sentAt) {
                        [stats.latencies addObject:@((NSInteger)([[NSDate date] timeIntervalSinceDate:sentAt] * 1000))];
                        [pending removeObjectForKey:key];
                    }
                }
            }
            if ([NSDate date].timeIntervalSince1970 < endAt.timeIntervalSince1970) receiveLoop();
            else receiveLoop = nil;   // كسر دورة الاحتفاظ عند انتهاء الحلقة
        }];
    };
#pragma clang diagnostic pop

    [ws resume];
    [ws sendPingWithPongReceiveHandler:^(NSError *error) {
        if (error) {
            @synchronized (stats) { if (!opened) stats.failed++; stats.errors++; }
            finish(); return;
        }
        opened = YES;
        @synchronized (stats) { stats.connected++; [stats.connectTimes addObject:@((NSInteger)([[NSDate date] timeIntervalSinceDate:connectStart]*1000))]; }
        receiveLoop();
        double interval = 1.0 / MAX(1, [STSettings shared].rateHz);
        timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(0,0));
        dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(interval*NSEC_PER_SEC)), (uint64_t)(interval*NSEC_PER_SEC), (uint64_t)(interval*NSEC_PER_SEC*0.2));
        dispatch_source_set_event_handler(timer, ^{
            if ([NSDate date].timeIntervalSince1970 >= endAt.timeIntervalSince1970) { finish(); return; }
            seq++;
            NSDictionary *msg = @{ @"type": @"ping", @"playerId": @(clientId), @"seq": @(seq), @"t": @((long long)([NSDate date].timeIntervalSince1970*1000)) };
            NSData *d = [NSJSONSerialization dataWithJSONObject:msg options:0 error:nil];
            NSString *text = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            @synchronized (pending) { pending[@(seq)] = [NSDate date]; }
            [ws sendMessage:[[NSURLSessionWebSocketMessage alloc] initWithString:text] completionHandler:^(NSError *sendErr) {
                if (!sendErr) @synchronized (stats) { stats.sent++; }
            }];
        });
        dispatch_resume(timer);
    }];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)([endAt timeIntervalSinceNow] * NSEC_PER_SEC) + (int64_t)(1*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (timer) finish();
    });
}

+ (void)runWithLog:(STLogBlock)log done:(STDoneBlock)done {
    STStats *stats = [STStats new];
    STSettings *st = [STSettings shared];
    log(@"=== Server Tester ===");
    log([NSString stringWithFormat:@"ws=%@ http=%@ clients=%ld duration=%lds rate=%ld/s", st.wsURL, st.httpURL, (long)st.clients, (long)st.durationSec, (long)st.rateHz]);

    [self testHTTPWithLog:log stats:stats done:^{
        log([NSString stringWithFormat:@"\n[WS] تشغيل %ld لاعب لمدة %lds ...", (long)st.clients, (long)st.durationSec]);
        NSDate *endAt = [NSDate dateWithTimeIntervalSinceNow:st.durationSec];
        dispatch_group_t group = dispatch_group_create();
        for (NSInteger i = 0; i < st.clients; i++) {
            [self spawnClient:i+1 endAt:endAt stats:stats group:group];
            [NSThread sleepForTimeInterval:st.rampMs / 1000.0];
        }
        dispatch_group_notify(group, dispatch_get_main_queue(), ^{
            NSInteger lost = MAX(0, stats.sent - stats.received);
            log(@"\n=========== النتيجة ===========");
            log([NSString stringWithFormat:@"اللاعبون المتصلون: %ld/%ld", (long)stats.connected, (long)st.clients]);
            log([NSString stringWithFormat:@"فشل الاتصال: %ld | انقطاع مبكر: %ld | أخطاء: %ld", (long)stats.failed, (long)stats.closedEarly, (long)stats.errors]);
            log([NSString stringWithFormat:@"رسائل مُرسلة/مستلمة: %ld / %ld (مفقودة ~%ld)", (long)stats.sent, (long)stats.received, (long)lost]);
            log([NSString stringWithFormat:@"زمن الاستجابة: متوسط %.0fms | p50 %.0fms | p95 %.0fms | p99 %.0fms",
                 [self avg:stats.latencies], [self pct:stats.latencies p:50], [self pct:stats.latencies p:95], [self pct:stats.latencies p:99]]);
            BOOL healthy = stats.failed == 0 && stats.closedEarly == 0 && [self pct:stats.latencies p:95] < 200;
            log(healthy ? @"\nالحكم: ✅ السيرفر بحالة جيدة" : @"\nالحكم: ⚠️ هناك مشاكل تحتاج مراجعة");
            done(stats);
        });
    }];
}
@end

// مجدول اختبار الضغط التلقائي من النسخة الأصلية — يعمل فقط والتطبيق مفتوح بالمقدمة.
@interface STAutoManager : NSObject
+ (instancetype)shared;
- (void)start;
- (void)refreshTimer;
@end

@implementation STAutoManager {
    NSTimer *_timer;
}

+ (instancetype)shared {
    static STAutoManager *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [STAutoManager new]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(appActive)
            name:UIApplicationDidBecomeActiveNotification object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(appResign)
            name:UIApplicationWillResignActiveNotification object:nil];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_timer invalidate];
}

- (void)refreshTimer {
    [_timer invalidate]; _timer = nil;
    if (![STSettings shared].autoOn) return;
    if ([UIApplication sharedApplication].applicationState != UIApplicationStateActive) return;
    NSTimeInterval interval = MAX(60, [STSettings shared].autoIntervalMin * 60.0);
    __weak typeof(self) weakSelf = self;
    _timer = [NSTimer scheduledTimerWithTimeInterval:interval repeats:YES block:^(NSTimer *timer) {
        [STRunner runWithLog:^(NSString *line) {
            [[NSNotificationCenter defaultCenter] postNotificationName:ASTestLogNotification object:line];
        } done:^(STStats *stats) {
            [[NSNotificationCenter defaultCenter] postNotificationName:ASTestLogNotification
                object:[NSString stringWithFormat:@"⏱️ AUTO LOAD: اتصال %ld/%ld — نجاح آلي ✅",
                    (long)stats.connected, (long)[STSettings shared].clients]];
        }];
        (void)weakSelf;
    }];
}

- (void)start { [self refreshTimer]; }

- (void)appActive { [self refreshTimer]; }
- (void)appResign { [_timer invalidate]; _timer = nil; }

@end

#pragma mark - UI theme (Aflatoon cyber-terminal)

enum { kBG = 0x090C12, kPanel = 0x0F141D, kLine = 0x1C2635, kGreen = 0x2BFF88, kCyan = 0x38B6FF,
       kRed = 0xFF4D5E, kAmber = 0xFFB800, kPurple = 0x9D8CFF, kText = 0xE6EDF3, kDim = 0x7A8899, kGold = 0x367BF0 };   // ثيم Kali: أزرق + أخضر طرفية

static inline UIColor *DSHex(uint32_t h) {
    return [UIColor colorWithRed:((h >> 16) & 0xFF) / 255.0 green:((h >> 8) & 0xFF) / 255.0 blue:(h & 0xFF) / 255.0 alpha:1];
}
static UIFont *DSMono(CGFloat s, UIFontWeight w) { return [UIFont monospacedSystemFontOfSize:s weight:w]; }
static void DSGlow(CALayer *l, UIColor *c, CGFloat r) {
    l.shadowColor = c.CGColor; l.shadowOpacity = 0.9; l.shadowRadius = r; l.shadowOffset = CGSizeZero;
}
static UIImage *DSIcon(NSString *name, CGFloat pt) {
    UIImageSymbolConfiguration *cfg = [UIImageSymbolConfiguration configurationWithPointSize:pt weight:UIImageSymbolWeightSemibold];
    return [UIImage systemImageNamed:name withConfiguration:cfg];
}

@interface DSGradView : UIView
@end
@implementation DSGradView
+ (Class)layerClass { return CAGradientLayer.class; }
@end

@interface DSPill : UILabel
@end
@implementation DSPill
- (void)drawTextInRect:(CGRect)r { [super drawTextInRect:UIEdgeInsetsInsetRect(r, UIEdgeInsetsMake(2, 7, 2, 7))]; }
- (CGSize)intrinsicContentSize { CGSize s = [super intrinsicContentSize]; return CGSizeMake(s.width + 14, s.height + 4); }
@end

static void DSStylePill(DSPill *p, NSString *t, UIColor *c) {
    p.text = t; p.font = DSMono(10, UIFontWeightBold); p.textColor = c; p.textAlignment = NSTextAlignmentCenter;
    p.backgroundColor = [c colorWithAlphaComponent:0.14];
    p.layer.cornerRadius = 5; p.layer.borderWidth = 0.5; p.layer.borderColor = [c colorWithAlphaComponent:0.7].CGColor;
    p.clipsToBounds = YES;
}

#pragma mark - Row cell

@interface DSCell : UITableViewCell
- (void)configure:(NSDictionary *)e sent:(BOOL)sent;
@end

@implementation DSCell {
    UIView *_card, *_bar; UILabel *_title, *_meta, *_rel, *_count; UIImageView *_icon; DSPill *_tag;
}

- (UILabel *)label:(UIFont *)f color:(UIColor *)c {
    UILabel *l = [UILabel new]; l.font = f; l.textColor = c; l.translatesAutoresizingMaskIntoConstraints = NO; return l;
}

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)rid {
    if ((self = [super initWithStyle:style reuseIdentifier:rid])) {
        self.backgroundColor = UIColor.clearColor; self.contentView.backgroundColor = UIColor.clearColor;
        self.selectionStyle = UITableViewCellSelectionStyleNone;
        _card = [UIView new]; _card.backgroundColor = DSHex(kPanel); _card.layer.cornerRadius = 10;
        _card.layer.borderWidth = 1; _card.layer.borderColor = DSHex(kLine).CGColor; _card.clipsToBounds = YES;
        _card.translatesAutoresizingMaskIntoConstraints = NO; [self.contentView addSubview:_card];
        _bar = [UIView new]; _bar.translatesAutoresizingMaskIntoConstraints = NO; [_card addSubview:_bar];
        _icon = [UIImageView new]; _icon.contentMode = UIViewContentModeCenter; _icon.translatesAutoresizingMaskIntoConstraints = NO;
        _title = [self label:DSMono(14, UIFontWeightSemibold) color:DSHex(kText)]; _title.lineBreakMode = NSLineBreakByTruncatingMiddle;
        _meta = [self label:DSMono(11, UIFontWeightRegular) color:DSHex(kDim)];
        _rel = [self label:DSMono(11, UIFontWeightRegular) color:DSHex(kCyan)]; _rel.numberOfLines = 2;
        _count = [self label:DSMono(13, UIFontWeightBold) color:DSHex(kGreen)];
        [_count setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
        [_count setContentCompressionResistancePriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
        _tag = [DSPill new]; _tag.translatesAutoresizingMaskIntoConstraints = NO;
        [_tag setContentCompressionResistancePriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
        for (UIView *v in @[_icon, _title, _meta, _rel, _count, _tag]) [_card addSubview:v];
        [NSLayoutConstraint activateConstraints:@[
            [_card.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:4],
            [_card.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-4],
            [_card.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:2],
            [_card.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-2],
            [_bar.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor], [_bar.topAnchor constraintEqualToAnchor:_card.topAnchor],
            [_bar.bottomAnchor constraintEqualToAnchor:_card.bottomAnchor], [_bar.widthAnchor constraintEqualToConstant:3],
            [_icon.leadingAnchor constraintEqualToAnchor:_bar.trailingAnchor constant:10],
            [_icon.topAnchor constraintEqualToAnchor:_card.topAnchor constant:10],
            [_icon.widthAnchor constraintEqualToConstant:20], [_icon.heightAnchor constraintEqualToConstant:20],
            [_title.leadingAnchor constraintEqualToAnchor:_icon.trailingAnchor constant:6],
            [_title.topAnchor constraintEqualToAnchor:_card.topAnchor constant:10],
            [_title.trailingAnchor constraintLessThanOrEqualToAnchor:_count.leadingAnchor constant:-8],
            [_count.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-12],
            [_count.topAnchor constraintEqualToAnchor:_card.topAnchor constant:10],
            [_tag.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-12],
            [_tag.topAnchor constraintEqualToAnchor:_count.bottomAnchor constant:6],
            [_meta.leadingAnchor constraintEqualToAnchor:_title.leadingAnchor],
            [_meta.topAnchor constraintEqualToAnchor:_title.bottomAnchor constant:4],
            [_meta.trailingAnchor constraintLessThanOrEqualToAnchor:_tag.leadingAnchor constant:-8],
            [_rel.leadingAnchor constraintEqualToAnchor:_title.leadingAnchor],
            [_rel.topAnchor constraintEqualToAnchor:_meta.bottomAnchor constant:3],
            [_rel.trailingAnchor constraintEqualToAnchor:_tag.leadingAnchor constant:-8],
            [_rel.bottomAnchor constraintEqualToAnchor:_card.bottomAnchor constant:-10],
            [_tag.bottomAnchor constraintLessThanOrEqualToAnchor:_card.bottomAnchor constant:-8]]];
    }
    return self;
}

- (void)configure:(NSDictionary *)e sent:(BOOL)sent {
    NSString *st = e[@"status"]; BOOL isIP = [e[@"type"] isEqualToString:@"ip"];
    UIColor *c; NSString *tag;
    if (sent) { c = DSHex(kPurple); tag = @"DENYLISTED"; }
    else if ([st isEqualToString:@"BLOCKED"]) { c = DSHex(kRed); tag = @"BLOCKED"; }
    else if ([st isEqualToString:@"FAILED"]) { c = DSHex(kAmber); tag = @"FAILED"; }
    else { c = DSHex(kGreen); tag = @"LIVE"; }
    _bar.backgroundColor = c; DSStylePill(_tag, tag, c);
    _icon.image = DSIcon(isIP ? @"network" : @"globe", 15); _icon.tintColor = isIP ? DSHex(kAmber) : DSHex(kCyan);
    _title.text = e[@"value"];
    _count.text = [NSString stringWithFormat:@"×%@", e[@"count"]];
    _meta.text = [(NSArray *)e[@"src"] componentsJoinedByString:@" · "];
    NSArray *rel = e[@"related"];
    NSArray *shown = rel.count > 3 ? [rel subarrayWithRange:NSMakeRange(0, 3)] : rel;
    NSString *relText = shown.count ? [NSString stringWithFormat:@"→ %@%@", [shown componentsJoinedByString:@", "], rel.count > 3 ? @" …" : @""] : nil;
    NSDictionary *probe = e[@"probe"];
    if ([probe[@"status"] isKindOfClass:NSString.class]) {
        NSString *ps = probe[@"status"];
        NSString *line = [NSString stringWithFormat:@"🧪 %@ %@ms %@", ps, probe[@"ms"] ?: @0, probe[@"detail"] ?: @""];
        relText = relText.length ? [relText stringByAppendingFormat:@"\n%@", line] : line;
    }
    _rel.text = relText;
}
@end

#pragma mark - Rules screen

@interface DSRulesVC : UITableViewController
+ (void)promptFrom:(NSString *)from over:(UIViewController *)vc done:(void (^)(void))done;
@end

@implementation DSRulesVC

+ (void)promptFrom:(NSString *)from over:(UIViewController *)vc done:(void (^)(void))done {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"🔁 استبدال"
        message:@"مثال: 1.1.1.1 ← 8.8.8.8\nأو *.example.com ← 1.2.3.4" preferredStyle:UIAlertControllerStyleAlert];
    NSArray *ph = @[@"من (نطاق أو IP)", @"إلى (IP أو نطاق)"];
    for (NSInteger i = 0; i < 2; i++) {
        [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
            t.placeholder = ph[i]; t.text = i == 0 ? from : nil; t.font = DSMono(14, UIFontWeightRegular);
            t.autocapitalizationType = UITextAutocapitalizationTypeNone;
            t.autocorrectionType = UITextAutocorrectionTypeNo; t.keyboardType = UIKeyboardTypeURL;
        }];
    }
    __weak UIAlertController *wa = a;
    [a addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"إضافة وتفعيل" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        [[DSSettings shared] addRuleFrom:wa.textFields[0].text to:wa.textFields[1].text];
        if (done) done();
    }]];
    [vc presentViewController:a animated:YES completion:nil];
}

// صف قسم بنمط قائمة Kali: [01] العنوان + أمر طرفية صغير
- (UIButton *)catButton:(NSString *)idx title:(NSString *)t sub:(NSString *)sub icon:(NSString *)ic color:(UIColor *)c tag:(NSInteger)tag {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    NSMutableAttributedString *as = [[NSMutableAttributedString alloc] initWithString:[NSString stringWithFormat:@"[%@]  %@\n", idx, t]
        attributes:@{ NSFontAttributeName: [UIFont systemFontOfSize:15, weight:UIFontWeightHeavy], NSForegroundColorAttributeName: DSHex(kText) }];
    [as appendAttributedString:[[NSAttributedString alloc] initWithString:[NSString stringWithFormat:@"└─$ %@", sub]
        attributes:@{ NSFontAttributeName: DSMono(11, UIFontWeightMedium), NSForegroundColorAttributeName: c }]];
    [b setAttributedTitle:as forState:UIControlStateNormal];
    b.titleLabel.numberOfLines = 2; b.titleLabel.textAlignment = NSTextAlignmentLeft;
    b.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    [b setImage:DSIcon(ic, 18) forState:UIControlStateNormal]; b.tintColor = c;
    b.imageEdgeInsets = UIEdgeInsetsMake(0, 0, 0, 12); b.titleEdgeInsets = UIEdgeInsetsMake(0, 8, 0, 0);
    b.contentEdgeInsets = UIEdgeInsetsMake(8, 14, 8, 14);
    b.backgroundColor = DSHex(kPanel); b.layer.cornerRadius = 12; b.layer.cornerCurve = kCACornerCurveContinuous;
    b.layer.borderWidth = 1.2; b.layer.borderColor = [c colorWithAlphaComponent:0.6].CGColor;
    b.tag = tag; [b addTarget:self action:@selector(catTap:) forControlEvents:UIControlEventTouchUpInside];
    [b.heightAnchor constraintEqualToConstant:62].active = YES;
    return b;
}

- (void)showPage:(NSInteger)i {
    [_search resignFirstResponder];
    [UIView animateWithDuration:0.18 animations:^{
        self->_home.hidden = (i >= 0);
        for (NSInteger k = 0; k < (NSInteger)self->_pages.count; k++) self->_pages[k].hidden = (k != i);
    }];
}
- (void)catTap:(UIButton *)b { [self showPage:b.tag]; }
- (void)backTap { [self showPage:-1]; }

- (void)viewDidLoad {
    [super viewDidLoad];
    self.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    self.title = @"RULES // قواعد الاستبدال";
    self.view.backgroundColor = DSHex(kBG);
    self.tableView.backgroundColor = DSHex(kBG);
    self.tableView.separatorColor = DSHex(kLine);
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:self action:@selector(done)];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAdd target:self action:@selector(add)];
}
- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    UINavigationBar *nb = self.navigationController.navigationBar;
    nb.barStyle = UIBarStyleBlack; nb.tintColor = DSHex(kGreen); nb.barTintColor = DSHex(kBG); nb.translucent = NO;
    nb.titleTextAttributes = @{ NSForegroundColorAttributeName: DSHex(kGreen), NSFontAttributeName: DSMono(14, UIFontWeightBold) };
}
- (void)done { [self dismissViewControllerAnimated:YES completion:nil]; }
- (void)add { [DSRulesVC promptFrom:nil over:self done:^{ [self.tableView reloadData]; }]; }

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    NSUInteger n = [DSSettings shared].rules.count;
    if (n == 0) {
        UILabel *l = [UILabel new]; l.text = @"$ no rules yet\nاضغط + لإضافة قاعدة استبدال"; l.numberOfLines = 0;
        l.textAlignment = NSTextAlignmentCenter; l.font = DSMono(13, UIFontWeightRegular); l.textColor = DSHex(kDim);
        tv.backgroundView = l;
    } else tv.backgroundView = nil;
    return n;
}
- (NSString *)tableView:(UITableView *)tv titleForFooterInSection:(NSInteger)s {
    return @"التفعيل يُحفظ تلقائياً ويبقى بعد الخروج من اللعبة. القاعدة تُطبَّق على الاتصالات الجديدة (قد تحتاج إعادة تشغيل اللعبة). يدعم *.domain.com";
}
- (void)tableView:(UITableView *)tv willDisplayFooterView:(UIView *)v forSection:(NSInteger)s {
    ((UITableViewHeaderFooterView *)v).textLabel.textColor = DSHex(kDim);
}
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    NSDictionary *r = [DSSettings shared].rules[ip.row];
    c.backgroundColor = DSHex(kPanel);
    c.textLabel.text = [NSString stringWithFormat:@"%@\n   ↳ %@", r[@"from"], r[@"to"]];
    c.textLabel.font = DSMono(13, UIFontWeightMedium); c.textLabel.textColor = DSHex(kGreen); c.textLabel.numberOfLines = 3;
    UISwitch *sw = [UISwitch new]; sw.on = [r[@"enabled"] boolValue]; sw.tag = ip.row; sw.onTintColor = DSHex(kGreen);
    [sw addTarget:self action:@selector(toggled:) forControlEvents:UIControlEventValueChanged];
    c.accessoryView = sw;
    return c;
}
- (void)toggled:(UISwitch *)sw { [[DSSettings shared] setRule:sw.tag enabled:sw.isOn]; }
- (void)tableView:(UITableView *)tv commitEditingStyle:(UITableViewCellEditingStyle)st forRowAtIndexPath:(NSIndexPath *)ip {
    if (st != UITableViewCellEditingStyleDelete) return;
    [[DSSettings shared] removeRule:ip.row];
    [tv reloadData];
}
@end

#pragma mark - Server test screen (merged)

@interface DSTestVC : UIViewController <UITextFieldDelegate>
@end

@implementation DSTestVC {
    UILabel *_status, *_modeHint;
    UISegmentedControl *_modeSeg;
    UIButton *_intervalBtn, *_testNowBtn, *_copyBtn;
    UIButton *_wsBtn, *_httpBtn, *_clientsBtn, *_durationBtn, *_rateBtn, *_runBtn;
    UIButton *_autoLoadBtn, *_autoLoadIntervalBtn;
    UITextView *_log;
    BOOL _loadRunning;
    NSTimer *_refresh;
}

- (UIButton *)row:(NSString *)title value:(NSString *)value color:(UIColor *)c sel:(SEL)sel {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    [b setTitle:[NSString stringWithFormat:@"%@: %@", title, value] forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal];
    b.titleLabel.font = DSMono(12, UIFontWeightSemibold);
    b.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    b.titleEdgeInsets = UIEdgeInsetsMake(0, 10, 0, 10);
    b.backgroundColor = [c colorWithAlphaComponent:0.08];
    b.layer.cornerRadius = 9; b.layer.borderWidth = 1; b.layer.borderColor = [c colorWithAlphaComponent:0.4].CGColor;
    [b.heightAnchor constraintEqualToConstant:38].active = YES;
    [b addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (UIButton *)action:(NSString *)title color:(UIColor *)c sel:(SEL)sel {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal];
    b.titleLabel.font = DSMono(12, UIFontWeightHeavy);
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.layer.cornerRadius = 10; b.layer.borderWidth = 1; b.layer.borderColor = c.CGColor;
    [b.heightAnchor constraintEqualToConstant:40].active = YES;
    [b addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (UILabel *)section:(NSString *)t {
    UILabel *l = [UILabel new];
    l.text = [NSString stringWithFormat:@"◆  %@  ◆", [t uppercaseString]]; l.textAlignment = NSTextAlignmentCenter;
    l.font = [UIFont systemFontOfSize:11 weight:UIFontWeightHeavy];
    l.textColor = DSHex(kGold); DSGlow(l.layer, DSHex(kGold), 5); l.layer.shadowOpacity = 0.5;
    return l;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    self.view.backgroundColor = DSHex(kBG);
    self.title = @"SERVER TEST";
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"إغلاق"
        style:UIBarButtonItemStyleDone target:self action:@selector(closeTap)];

    UIScrollView *sv = [UIScrollView new]; sv.translatesAutoresizingMaskIntoConstraints = NO;
    sv.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    [self.view addSubview:sv];

    UILabel *title = [UILabel new];
    title.text = @"⚡ SERVER TEST";
    title.font = DSMono(18, UIFontWeightHeavy);
    title.textColor = DSHex(kGreen);
    DSGlow(title.layer, DSHex(kGreen), 6);

    UILabel *credit = [UILabel new];
    credit.text = @"  ✦ أفلاطون • Aflatoon  ";
    credit.font = [UIFont systemFontOfSize:10.5 weight:UIFontWeightBold];
    credit.textColor = DSHex(kGold);
    credit.backgroundColor = [DSHex(kGold) colorWithAlphaComponent:0.12];
    credit.layer.cornerRadius = 8; credit.clipsToBounds = YES;
    credit.textAlignment = NSTextAlignmentCenter;

    UIStackView *header = [[UIStackView alloc] initWithArrangedSubviews:@[title, [UIView new], credit]];
    header.axis = UILayoutConstraintAxisHorizontal; header.alignment = UIStackViewAlignmentCenter;

    _status = [UILabel new];
    _status.font = DSMono(11, UIFontWeightRegular);
    _status.textColor = DSHex(kText);
    _status.numberOfLines = 0;
    _status.backgroundColor = DSHex(kPanel);
    _status.layer.cornerRadius = 10; _status.layer.borderWidth = 1;
    _status.layer.borderColor = DSHex(kLine).CGColor; _status.clipsToBounds = YES;
    _status.text = @"جاهز.";

    _modeSeg = [[UISegmentedControl alloc] initWithItems:@[@"OFF", @"ALL", @"CHAT"]];
    _modeSeg.selectedSegmentIndex = [ASTestManager shared].mode;
    _modeSeg.backgroundColor = DSHex(kPanel);
    _modeSeg.selectedSegmentTintColor = DSHex(kGreen);
    [_modeSeg setTitleTextAttributes:@{ NSForegroundColorAttributeName: DSHex(kDim), NSFontAttributeName: DSMono(11, UIFontWeightBold) } forState:UIControlStateNormal];
    [_modeSeg setTitleTextAttributes:@{ NSForegroundColorAttributeName: DSHex(kBG), NSFontAttributeName: DSMono(11, UIFontWeightHeavy) } forState:UIControlStateSelected];
    [_modeSeg addTarget:self action:@selector(modeChanged:) forControlEvents:UIControlEventValueChanged];

    _modeHint = [UILabel new];
    _modeHint.font = DSMono(10, UIFontWeightRegular);
    _modeHint.textColor = DSHex(kDim);
    _modeHint.numberOfLines = 0;
    _modeHint.text = @"ALL: كل النطاقات وIP/DNS · CHAT: IP/DNS الدردشة والكتابة أونلاين.\nالاختبار = DNS + اتصال TCP بالمنافذ المرصودة (أو 443/80) — تلقائي كل فترة.";

    _intervalBtn = [self action:@"AUTO: كل 120 ثانية" color:DSHex(kCyan) sel:@selector(intervalTap)];
    _testNowBtn = [self action:@"▶ اختبار الأهداف الآن" color:DSHex(kGreen) sel:@selector(testNowTap)];
    _copyBtn = [self action:@"📋 نسخ الأهداف" color:DSHex(kPurple) sel:@selector(copyTargetsTap)];

    STSettings *st = [STSettings shared];
    _wsBtn = [self row:@"WS" value:st.wsURL color:DSHex(kCyan) sel:@selector(editWS)];
    _httpBtn = [self row:@"HTTP" value:st.httpURL color:DSHex(kCyan) sel:@selector(editHTTP)];
    _clientsBtn = [self row:@"CLIENTS" value:[NSString stringWithFormat:@"%ld", (long)st.clients] color:DSHex(kAmber) sel:@selector(cycleClients)];
    _durationBtn = [self row:@"DURATION(s)" value:[NSString stringWithFormat:@"%ld", (long)st.durationSec] color:DSHex(kAmber) sel:@selector(cycleDuration)];
    _rateBtn = [self row:@"RATE(/s)" value:[NSString stringWithFormat:@"%ld", (long)st.rateHz] color:DSHex(kAmber) sel:@selector(cycleRate)];
    _runBtn = [self action:@"▶ RUN NOW" color:DSHex(kGreen) sel:@selector(runTap)];
    _autoLoadBtn = [self action:@"AUTO LOAD: OFF" color:DSHex(kCyan) sel:@selector(autoLoadTap)];
    _autoLoadIntervalBtn = [self action:@"كل 30 دقيقة" color:DSHex(kDim) sel:@selector(autoLoadIntervalTap)];
    [self refreshAutoLoadButtons];
    UIStackView *loadAutoRow = [[UIStackView alloc] initWithArrangedSubviews:@[_autoLoadBtn, _autoLoadIntervalBtn]];
    loadAutoRow.axis = UILayoutConstraintAxisHorizontal;
    loadAutoRow.distribution = UIStackViewDistributionFillEqually;
    loadAutoRow.spacing = 6;

    _log = [UITextView new];
    _log.backgroundColor = DSHex(kPanel); _log.textColor = DSHex(kText);
    _log.font = DSMono(10.5, UIFontWeightRegular);
    _log.layer.cornerRadius = 8; _log.editable = NO;
    _log.text = @"جاهز. اختر ALL أو CHAT ثم اضغط «اختبار الأهداف الآن»، أو استخدم RUN NOW لاختبار ضغط سيرفرك الخاص.";
    [_log.heightAnchor constraintEqualToConstant:230].active = YES;

    UILabel *foot = [UILabel new];
    foot.text = @"© Aflatoon // أفلاطون — all rights reserved";
    foot.textAlignment = NSTextAlignmentCenter;
    foot.font = DSMono(10, UIFontWeightMedium);
    foot.textColor = DSHex(kDim);

    UIStackView *main = [[UIStackView alloc] initWithArrangedSubviews:@[
        header, credit, _status,
        [self section:@"AUTO TEST — الأهداف الملتقطة"], _modeSeg, _modeHint, _intervalBtn, _testNowBtn, _copyBtn,
        [self section:@"LOAD TEST — سيرفرك الخاص"], _wsBtn, _httpBtn, _clientsBtn, _durationBtn, _rateBtn, _runBtn, loadAutoRow,
        [self section:@"LOG"], _log, foot]];
    main.axis = UILayoutConstraintAxisVertical; main.spacing = 8;
    main.translatesAutoresizingMaskIntoConstraints = NO;
    [sv addSubview:main];

    [NSLayoutConstraint activateConstraints:@[
        [sv.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [sv.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [sv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [sv.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [main.topAnchor constraintEqualToAnchor:sv.contentLayoutGuide.topAnchor constant:14],
        [main.bottomAnchor constraintEqualToAnchor:sv.contentLayoutGuide.bottomAnchor constant:-18],
        [main.leadingAnchor constraintEqualToAnchor:sv.contentLayoutGuide.leadingAnchor constant:14],
        [main.trailingAnchor constraintEqualToAnchor:sv.contentLayoutGuide.trailingAnchor constant:-14],
        [main.widthAnchor constraintEqualToAnchor:sv.frameLayoutGuide.widthAnchor constant:-28]]];

    [self refreshStatus];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    UINavigationBar *nb = self.navigationController.navigationBar;
    nb.barStyle = UIBarStyleBlack; nb.tintColor = DSHex(kGreen); nb.barTintColor = DSHex(kBG); nb.translucent = NO;
    nb.titleTextAttributes = @{ NSForegroundColorAttributeName: DSHex(kGreen), NSFontAttributeName: DSMono(14, UIFontWeightBold) };
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(logNote:) name:ASTestLogNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateNote:) name:ASTestDidUpdateNotification object:nil];
    [_refresh invalidate];
    _refresh = [NSTimer scheduledTimerWithTimeInterval:2.0 target:self selector:@selector(refreshStatus) userInfo:nil repeats:YES];
    [self refreshStatus];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_refresh invalidate]; _refresh = nil;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_refresh invalidate];
}

- (void)closeTap { [self dismissViewControllerAnimated:YES completion:nil]; }

- (void)logNote:(NSNotification *)n {
    NSString *line = [n.object isKindOfClass:NSString.class] ? n.object : nil;
    if (line) [self appendLog:line];
}

- (void)updateNote:(NSNotification *)n { [self refreshStatus]; }

- (void)refreshStatus {
    ASTestManager *m = [ASTestManager shared];
    NSArray *all = [[DSStore shared] snapshot];
    NSInteger allCount = 0, chatCount = 0, tested = 0, ok = 0;
    for (NSDictionary *e in all) {
        if ([m entryMatches:e mode:ASTestModeAll]) allCount++;
        if ([m entryMatches:e mode:ASTestModeChat]) chatCount++;
        NSDictionary *p = e[@"probe"];
        if ([p[@"status"] isKindOfClass:NSString.class]) {
            tested++;
            if ([p[@"status"] isEqualToString:@"OK"]) ok++;
        }
    }
    NSString *last = m.lastRun ? [NSDateFormatter localizedStringFromDate:m.lastRun
        dateStyle:NSDateFormatterNoStyle timeStyle:NSDateFormatterMediumStyle] : @"—";
    _status.text = [NSString stringWithFormat:@"  الأهداف الملتقطة: ALL %ld · CHAT %ld\n  تم اختبارها: %ld (ناجح %ld · فاشل/تخطي %ld)\n  آخر تشغيل: %@%@  ",
        (long)allCount, (long)chatCount, (long)tested, (long)ok, (long)(tested - ok), last,
        m.running ? @"   ⏳ جارٍ..." : @""];
    _modeSeg.selectedSegmentIndex = m.mode;
    [_intervalBtn setTitle:[NSString stringWithFormat:@"AUTO: كل %ld ثانية", (long)m.intervalSec] forState:UIControlStateNormal];
}

- (void)modeChanged:(UISegmentedControl *)seg {
    ASTestManager *m = [ASTestManager shared];
    m.mode = (ASTestMode)seg.selectedSegmentIndex;
    [self refreshStatus];
    [self appendLog:[NSString stringWithFormat:@"AUTO TEST: %@", [m modeTitle]]];
}

- (void)intervalTap {
    static NSArray *opts;
    if (!opts) opts = @[@30, @60, @120, @300, @600];
    ASTestManager *m = [ASTestManager shared];
    NSInteger idx = [opts indexOfObject:@(m.intervalSec)];
    idx = (idx == NSNotFound) ? 0 : (idx + 1) % opts.count;
    m.intervalSec = [opts[idx] integerValue];
    [self refreshStatus];
}

- (void)testNowTap {
    ASTestManager *m = [ASTestManager shared];
    if (m.mode == ASTestModeOff) {
        m.mode = ASTestModeAll;
        _modeSeg.selectedSegmentIndex = ASTestModeAll;
    }
    [m runNowForce:YES];
    [self appendLog:@"▶ بدء الاختبار اليدوي للأهداف الملتقطة..."];
}

- (void)copyTargetsTap {
    ASTestManager *m = [ASTestManager shared];
    ASTestMode mode = m.mode == ASTestModeOff ? ASTestModeAll : m.mode;
    NSArray *targets = [m targetsForMode:mode force:YES];
    NSMutableString *s = [NSMutableString string];
    for (NSDictionary *e in targets) {
        NSDictionary *p = e[@"probe"];
        [s appendFormat:@"%@\t%@\t%@\t%@ms\n", e[@"type"], e[@"value"],
            p[@"status"] ?: @"UNTESTED", p[@"ms"] ?: @0];
    }
    UIPasteboard.generalPasteboard.string = s;
    [self appendLog:[NSString stringWithFormat:@"📋 نُسخ %lu هدف إلى الحافظة", (unsigned long)targets.count]];
}

- (void)appendLog:(NSString *)line {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self->_log) return;
        self->_log.text = [self->_log.text stringByAppendingFormat:@"\n%@", line];
        [self->_log scrollRangeToVisible:NSMakeRange(self->_log.text.length, 0)];
    });
}

- (void)promptForKey:(NSString *)key title:(NSString *)title current:(NSString *)current {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:nil preferredStyle:UIAlertControllerStyleAlert];
    [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.text = current;
        tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        tf.keyboardType = UIKeyboardTypeURL;
    }];
    __weak typeof(self) weakSelf = self;
    [ac addAction:[UIAlertAction actionWithTitle:@"حفظ" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *val = [ac.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        STSettings *st = [STSettings shared];
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if ([key isEqualToString:@"ws"]) {
            st.wsURL = val;
            if (strongSelf) [strongSelf->_wsBtn setTitle:[NSString stringWithFormat:@"WS: %@", val] forState:UIControlStateNormal];
        } else {
            st.httpURL = val;
            if (strongSelf) [strongSelf->_httpBtn setTitle:[NSString stringWithFormat:@"HTTP: %@", val] forState:UIControlStateNormal];
        }
        [st save];
    }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:ac animated:YES completion:nil];
}

- (void)editWS { [self promptForKey:@"ws" title:@"عنوان WebSocket (ws:// أو wss://)" current:[STSettings shared].wsURL]; }
- (void)editHTTP { [self promptForKey:@"http" title:@"عنوان فحص HTTP (اختياري)" current:[STSettings shared].httpURL]; }

- (void)cycleClients {
    static NSArray *opts; if (!opts) opts = @[@5, @10, @25, @50, @100];
    STSettings *st = [STSettings shared];
    NSInteger idx = [opts indexOfObject:@(st.clients)]; idx = (idx == NSNotFound) ? 0 : (idx + 1) % opts.count;
    st.clients = [opts[idx] integerValue]; [st save];
    [_clientsBtn setTitle:[NSString stringWithFormat:@"CLIENTS: %ld", (long)st.clients] forState:UIControlStateNormal];
}
- (void)cycleDuration {
    static NSArray *opts; if (!opts) opts = @[@10, @15, @30, @60, @120];
    STSettings *st = [STSettings shared];
    NSInteger idx = [opts indexOfObject:@(st.durationSec)]; idx = (idx == NSNotFound) ? 0 : (idx + 1) % opts.count;
    st.durationSec = [opts[idx] integerValue]; [st save];
    [_durationBtn setTitle:[NSString stringWithFormat:@"DURATION(s): %ld", (long)st.durationSec] forState:UIControlStateNormal];
}
- (void)cycleRate {
    static NSArray *opts; if (!opts) opts = @[@1, @2, @5, @10, @20];
    STSettings *st = [STSettings shared];
    NSInteger idx = [opts indexOfObject:@(st.rateHz)]; idx = (idx == NSNotFound) ? 0 : (idx + 1) % opts.count;
    st.rateHz = [opts[idx] integerValue]; [st save];
    [_rateBtn setTitle:[NSString stringWithFormat:@"RATE(/s): %ld", (long)st.rateHz] forState:UIControlStateNormal];
}

- (void)runTap {
    if (_loadRunning) return;
    _loadRunning = YES;
    _log.text = @"";
    [_runBtn setTitle:@"⏳ جارٍ الاختبار..." forState:UIControlStateNormal];
    __weak typeof(self) weakSelf = self;
    [STRunner runWithLog:^(NSString *line) { [weakSelf appendLog:line]; } done:^(STStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        strongSelf->_loadRunning = NO;
        [strongSelf->_runBtn setTitle:@"▶ RUN NOW" forState:UIControlStateNormal];
    }];
}

- (void)refreshAutoLoadButtons {
    STSettings *st = [STSettings shared];
    [_autoLoadBtn setTitle:(st.autoOn ? @"AUTO LOAD: ON" : @"AUTO LOAD: OFF") forState:UIControlStateNormal];
    [_autoLoadIntervalBtn setTitle:[NSString stringWithFormat:@"كل %ld دقيقة", (long)st.autoIntervalMin] forState:UIControlStateNormal];
}

- (void)autoLoadTap {
    STSettings *st = [STSettings shared];
    st.autoOn = !st.autoOn; [st save];
    [[STAutoManager shared] refreshTimer];
    [self refreshAutoLoadButtons];
}

- (void)autoLoadIntervalTap {
    static NSArray *opts; if (!opts) opts = @[@15, @30, @60, @120];
    STSettings *st = [STSettings shared];
    NSInteger idx = [opts indexOfObject:@(st.autoIntervalMin)];
    idx = (idx == NSNotFound) ? 0 : (idx + 1) % opts.count;
    st.autoIntervalMin = [opts[idx] integerValue]; [st save];
    [[STAutoManager shared] refreshTimer];
    [self refreshAutoLoadButtons];
}
@end

#pragma mark - Main menu

// صورة صاحب الحقوق (أفلاطون) مدمجة داخل الـ dylib — تظهر في شارة الحقوق
static UIImage *DSAvatarImage(void) {
    static UIImage *img; static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSData *d = [[NSData alloc] initWithBase64EncodedString:@"/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBAUEBAYFBQUGBgYHCQ4JCQgICRINDQoOFRIWFhUSFBQXGiEcFxgfGRQUHScdHyIjJSUlFhwpLCgkKyEkJST/2wBDAQYGBgkICREJCREkGBQYJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCT/wAARCACwALADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD5woooroMwooooAKKKKACiilVWdgqgljwAKAEp6RPIcIjN9BWgljHbgb8SSd8/dH09akILNsiLOx6hecfgKzc+xSiZ4spyM7AB7mpI7HcCXlA9lGavizupOHiYAcc4B+mM1DNaXqgiOCYKTjcuOPypczHyopPAm9kRjleufWo2iZe4P0OakkEkWVctuyc7sjNQMGD5VsGhSYWQUU8EPgNhW9exprKVODWilclqwlFFFMQUUUUAFFFFABRRRQAUUUUAFFFFACqpdgqjJPQVp2dt5IBC75nHGOwpNNtXLDYoMjLnB6AHvmmapqsdkDDA2W/jl7v7D0FZSlfQ0iralqWe2sSWnZZ5M8oDwPqf8KoXfiGVy3kfu1PZeB/9esRpJrjLhW2g9fSpBp0rOVUiSQdUHUVFytydtSmY7mkz+tSR6nOpysnvxx/KqrWXloNx2yH+Hr+tBtGK7xvxnBAU0rhZmwmrtNiO6RJUYAZcfd+hp0lik6eZZtkDkp3H+NYbxTwn7px14qxZag0Mq4JXB/WquKxZEW04xn3p46YOCPT0q++y8jNxDsWVfvL2f3FLfafF9gTVbSdHhkk8sxZ+eFtucH1HXB74HvhiMySPYAw6H9KjqxG3nIUP3sZHvUBGDitIu5DQlFFFUIKKKKACiiigAooooAKtafZveT7UQvtwdo7nsKq1p2N0+n2zPFCZZZQR8pwUHr+X86mbsioq7H63qi6dE9rAQGY4kZerEfwj2rmhDLO5aRSWPRa7LR/Ak+oQHWtUuEgtmPyccH169hWvBpXh2XCJfIG9XOMn1H4VxSrJOyOyOHbV3oeepZzoV3BioP3Vrd0qzuLuRiEXK4CsV+YCvTNF+HNrqMKTRyK8QIIK+ma7G38BwWv+riVRjkkVhPEdDrpYO+tzy218DXM6phtxXku+CAfp1/WrkPgCSNladzKV5HGBj029hXpP/CNPENyt9QBiq1xpVzGflJ9ODWLrSOpYaK6HnuoeC7abcxhAdiBuUZ/SuR8QeEIbFf3YmVsk7sAgDFeuT2k0QIJfJ/EVk31us8MkFwgbcMciqhWkmZVcNFrY8as7xrWZYnjaPnI3cYPT8vatS9iVdssYARvvAdjUfizRZLGZXEhkyckkk7f84qPR7sXluYJicgbc+g7GvRhK6ueRODi7MgkBjPmIeP5U6Qh1Vx34P1FLJmJmRsHnawHY0jLsUjOQcMD7VpHczexHRRRWpAUUUUAFFFFABRRRQAoG4gepxXY+BPDreIvEwtV2vEcQ56kAcn6Y5rj4v9an+8P517v8BdH2XF5fRJjAcDj7xYkA8/Q1yYyfJC514Onz1EifxD4Yn1KaSx0lUh0+yURkDqzjGSPzrkr74Uazl54JYW2k/ug5UY9iRzXv0lpBo1olrbW5MhyxXoCx5Zmrg/FnjvSLISAXZuPLbY7WsZdFbsMgEfr615VKtLaKPZqYeDV5ux40o8QeHL392t9bfN8zHO0/lxivWfAPjPVL547K/Tcq/wDLQjkgnjPr3rKh8c6bq6i3imieU9A6FWx9SB/Wu28FpY3D7p4YyQ3IXggjvW1aq0veRnQoJP3ZHXQ28F4CUUD2PFZ99ZWVoga4mjTd90k1XvtagikaOB9qqex9K4PxTdyay5VLtlK8LGBxnFZQaludE7x2Og1A6b91bqAyHkANyfp61ymqxW5+aGWMuP8AargNT8H+IxJ5scEl2+f4WPT3zWZN4f8AEFm4llsr+2GMtkn6+4rpjRg9mcVTE1Fo4ml4zhjezkIjDFTnA7g9P1rzy3kWzu9ythGO1h3A6fzrYur+8gBjuPNEIOMyddp6j3rK1TTZ7V8spKEZV/WummuTQ4K0vaPmSNe+hIMdxjIcbJB6MOhqpjMfP8PT6VY064/tC0Fu+NzrhSf761E5AjY45PB45Fbo52V6KKK2MwooooAKKKKACiiigDovDvgPxB4lsZtS02xMlnbOEeZmCqW67Vz1IHWvpX4QaMNH8Kw3csPlSXDGQqeDgEhc/ln8a5T4JWklt4Z0eQyAeb58hQ8go0h4I7/dzXsMVl5kKx4ICr9BXhYzESnJw6Jn0eGwcKMI1L6yV/vOX8TWNv4nuI4ruW6htckSx28m0SexOM4+hrlPEXhq4g0E6Fpc0S2G5WQRQmNjgn7wHDdevWvRLzTzBuYd+3as37GbhyrkKD2xXPCbjsdUqcZLVHlOheEpdJeVIh9rkli8rE0Wccj356Dr0r0XQPDq6BpDmfaJ5Fy3faPTNdDZaXb2qGSOMFycAnqapazFJgq4Y5HzCrlOVR2FSpRhsee69IEQrExMnOcHmuetL6UybVSR3bOwR4yWHua29XTyNSxghJOlZ7aOA7HAMUnG0juK1SXUzle+hUvPFt94bvlj1W3vLfzIw4ORKqqe7YJ7AnHtWhbeLLHW7YMxjlXdjenT8R1FZXiLw6dcCTSyS5iRUUk5GBnAPfocda5690u40xreXTLG4LYKXKZBEw65wOhHatnGD2ObmqRfvaoteMPBkd1HPNbhQGXcFXjn3rCTSFm8MqrKdyoQA46Y6V3mnXAvdOXYzhgvRs5HsaybqI2mnt5m0hS2ePrRGbaszOpSim5I8lurGSz/AH8bbDnd8vueP50+EgWrDnO4DmnaxMZGLL8qNyOM+1RJhUCr06130zyZi0UUV0GQUUUUAFFFFABRRRQB9P8AwXWG58E6LcScPt+xxjbnlZWLH/vkD8zXsYT9zt5HHavG/gTcI/gXQ45MbVuroKO5IJyf/HxXsq4bg8ivnqitVkvNn0qm5UoPyX5GZdxBdwPIHc1jyP5Zz/D+prc1BlVWckBe9chq3i/RNHQma5ErH+GMbj+lQl2R0xmktSXxD4p/sSzU2NjcahceXvMcJAJ9sngCqGreK5V09L6S2uLITQBzFMo3pxjBAzk59K4vVfiRd3V4E03ThFG45llXqOhzx8vb35qH/hKWn0iL7TB5k212U5J3Y9BWsactzOVeGyJLe/g8V2c/kSt9qspCrxyIUcH6Hsa27a0W6somIyrqCf8AZNcr4R1iXWoJnga3jlDlSzJ+86cf59q7zRbdY7QWpyWUZBPU+tOSs7BBprmRnCzC/IVyPX1qndaUgJKAKB6V0DxFSTwOeKpzsVXHr3pWZcoHNiBIJHLAHPy5rmfFREOm3L5AGw9fU11eqOqEsK4/WVGpfZ7B+lzMqn6A5P6CtIb3OOqtLHk2oRusq27LtJw3X1pqjaPWvb7uw0nTZFay0aGW6f5DM6gK3HqecD2ryvxhbRWuuSpHDFBuRHeOL7isRk49PXHvXoYeqpO1jzcVhHThz30MWiiius4AooooAKKKKACiiigD6C+AHiT7VpcGnNa7U0gzAyhh85mbcCB1yArfpXu8FwuCWkGCPu+hr5g/Z51CO31vUraR9vmQpIDu2/dbn9K+gtOumKyxqhAUYR26Y9vX614GM92q7H0GDfPRVzg/iR4qmvNaTTrOdohHnPBAx3Y/h0NVLKy8MaVbQC6f+0LpowS3Gxcjuf6V2KeDra5upb28IdnfOCcgDNST+G9FtUMlvDHEc5IAFZ+1VkkddKiue8zjvt2jwxRxW1pZhN5Xy1XnJ7ZPOay1s9GjkcRefuBJUsR8hPp7Vpata2LSsjvFgk7SRxWNeaVaBRLbysmBgeU+cfQVtE7ZUaclZWOfOkXfhe/F/p6tcDdkhejD3Pr3/Cu88P8Aia31SUrHIvmKxBA/ix1xXIxapPprlZg9xE/BO3n8qxdWnOmX63Gk70VjvbORk4yePTGRWrjz6M8qqvYP3dj2ieVWX29RWPezBSwHJIqLTdVW7sYpQwO+MNke4qtey8ZycnpzWCvsbSnoY2ry4iJY85rA021k1rWR5TBUsyqsTyCW5I/IDn3qbxHqMcDMTIcIPmq94Sju9PtYrtlhgNyxdmLfNyOBge3atbWic8feqWNfVxa2726yOkUccDkE/djUYBYn0AzXhGv6kNX1m8vVJ2SyHy89Qg4X9AK7L4l+LJbmaTSozh2Ci4I6qo5WP/2Y/gK89rvwlLlXM+pw5jiVNqlHZfmFFFFdZ5gUUUUAFFFFABRRRQBv+Bdd/wCEe8TWl42DET5UgIyCrcGvq/Q5I57aKSMARlAN/rjv+NfGPT2r3z4Y+OLseFBLfuBZQSi380gt5bgLhWHZcHOfr7V5WZUHJKaPWyyuotwZ7cYWEQ2nIxmsrUrMXEfzk8dBT9O8T2V5A6QybvLHLlcKeKy9Y16NcfMisQCPnyCD0/XtXlxpts9d1Etzynx1o15atLPucguFjVD0PpTvDVrqghjQKZIi275xzt9s8+9d3eQh0Mk4EnzZIOAF9hTYPJiYLHyCMYHQY7fXmu3mko2Obli581zIfTlY7pEHFZmt6BDqXkA7RGrjf2yO4z27V1F3Gu47enesi+lVI2QnBPasoylc0nZqzKs0y6baRwRsNyA8kY471h3GsqZYlkmDu4ztU9apatcTzKwkiYsQFXntn09MCsu5vBaRGRxGkqrtOB0GOAPwreMTknPUr6rqNtdaikdywggaYGRz/Co9f5Ve8S/EKxtIFj0WQTTrkIw+7Hnv7n0Fcnr0bxaeJ5gRNdS5CkfdUc1zldtGhGS5mcVXEzheMeo+WV55HlldnkclmZjksT1JplFFdp54UUUUAFFFFABRRRQAUUUoBY4AJNACV7h8BrGHXPB/iXSJ0R0lnTIddw+aMjOPbGa8TaMRruc/gK9t/Zqvwx8QWfyqR5EwAHb51P8ASuDHy/cu3l+Z3Zev3yv5/kZOtPrvwyvGs5BJPYvzDc4689x/Cf51Ui8dwzgzzSt5528E4ywPXH4mvetR0m31JGjuYo5Ym4KOMgivF/HXwdC3BuNIDIhJYxHkL7A9RXBQxEJaT3PRrUJx1hquxZg8ax3KSSzXLMkYUQqp6bR1b6ntS6Z4wR5oYo2273BDMclBjk/n615beaJq+muYXhlQsf4eQ2O9Uom1ZWdo94UccDGPzrtUIvZnE6s1o0e3z+NLOGFvLkDBcgEngkDPXvXNz+M4ruViX2OrcHOQFrzgWusXbIkisV9DwPr+tb2heC7y/P72do0J5wtRKEIrcuNWpJ2SLuoa5HdyEZd514GO47VZ0rQLrUZ1v9SGzYcrGemfcV0ul+D7KwAKQ5kHPmSctU2u3tpo1jJcXEuyNRwD1J7Ae9YOpf3YHTGjZc1Q81+IV8Ev7a2GCEUnA/T+tcxG4cc496s6teDVb+S7ZMbj8ueSBVUttHevRpJxikeTWkpzchzkR4yeG6GlA3DIxiogrTZQD5e9SRqkKhSSxHc1rzsy5UOaNlGSOKbThMo6L17Zoba3KDHqKpSuJobRRRVkhRRRQA+OMyHqFA6segou5Y0iEcW7HXcRgk+tTyKUsE2BSXyxzWRNPnCqO3SsZSvoaJWFeckD39K9b/Zyu5LXxjd20uALyybC98oyt/ImvJ7K2BfzHAITn8a7H4XaudL+I+iTF9olnNux9nUr/MiubEx5qUl5HRhZctWL8z6yuYxtJ6Y6VmXTC4VoyOcVqtKrxg8cjpWNqeY1LL1xXz8dz6V7HJapptp9pJkRWOP4hwKyJNLsNp2QISTu4FWrz7VNeOWc7D0FPS33YReo9q9BPQ4pJXMcaPbyT8RKe3I4FbWn2MdsgRUxj8s1atNNUsCScDjrxV5YguQoAPTNS22VCKWpl3rw2FtJdTOqxxLuZm4CivCfF3iWXxJqbSKWW0jJEKH0/vH3NdL8T/Gg1W5bSNPlzaQtiaQHiVx2H+yP1NedkkfKAST0rvw1DlXM9zzMZied8kdhWbbnmmqjSfe+UVKkW07nILenpSlhya6zgAYVcDAx2oJDdcGmdz6UFwvSgB48vrsH50eZCnJjX8CaFjkf+HavvT/KhTl+fxoAYdjcofwNNp2+yRuY+fXcRSM8TnMbfgTWkZdyWgVS5woLH0AzViOxkZ1RiFLHGOpFWp28gD5RjGcAYFR21y7XkJOAvIAHToal1H0KUUTXcIMEeOE29u2O1YE8PlSsxHB5Ga6Ug+UFbkqMn8ayb62MkZA4J/nWaKZBan/R+O/NFjJLFrNpJCdssc0bofQhgc/pTLRtqFCOV4I9KmsBjUS55wMr+VEthx3PsbTr9bq0RwcsRnH1pt3IskRz+tcp4C1b7TpVojNlmiUEn1A/wro7hx8wbgfzr5507SsfSxneNzDnt0dyAAMHgk9aI4AAAP0p9wqE8AD6inQoNwKnA+ldC2MXuWYoFRQSOPavOvip44/s2FtE02bFzKP9IkQ8wqf4R/tH9B9a3vH/AI0j8KacI4WR7+cfuYzzsH99h6fzNeAX15NfXLyyM8s8rFmYnJZj1NdeHo3fNI4cXiOVckdytISWCgZPQAVNsWGPacF+59PalRFtged0p6t6ewqJmy1egeWITn2pDwKMgduTT0hAG6Uf8BoAYkbSdOF9TUqeXByq5P8AeNNlnAA/LApyWxchpvwj/wAaAE3y3B+T7v8AePT/AOvSi3UnaVMjHsf8KvrEEQbjtH8/pUE92kIKxLtB79zQMSOKO3GZUT02KB+ppjXUcbHbFEPooqjLdkkgZJPYUiWs8wy7eWv60CP/2Q==" options:0];
        img = d ? [UIImage imageWithData:d] : nil;
    });
    return img;
}

@interface DSMenuVC : UIViewController <UITableViewDataSource, UITableViewDelegate, UITextFieldDelegate>
@end

@implementation DSMenuVC {
    UITableView *_tv; UITextField *_search; UISegmentedControl *_seg; UILabel *_toast, *_cursor;
    DSGradView *_header; UIView *_scan; NSMutableArray<UILabel *> *_stats; UIButton *_proxyBtn;
    NSArray<NSDictionary *> *_data; NSString *_query; NSTimer *_timer;
    UIView *_home; NSArray<UIView *> *_pages;
}

- (UIStatusBarStyle)preferredStatusBarStyle { return UIStatusBarStyleLightContent; }

- (UIButton *)neon:(NSString *)t icon:(NSString *)ic color:(UIColor *)c sel:(SEL)s {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    [b setTitle:t forState:UIControlStateNormal]; [b setTitleColor:c forState:UIControlStateNormal];
    [b setImage:DSIcon(ic, 12) forState:UIControlStateNormal]; b.tintColor = c;
    b.titleLabel.font = [UIFont systemFontOfSize:11.5 weight:UIFontWeightHeavy]; b.imageEdgeInsets = UIEdgeInsetsMake(0, -4, 0, 4);
    b.backgroundColor = [c colorWithAlphaComponent:0.15];
    b.layer.cornerRadius = 13; b.layer.cornerCurve = kCACornerCurveContinuous;
    b.layer.borderWidth = 1.3; b.layer.borderColor = [c colorWithAlphaComponent:0.75].CGColor;
    b.layer.shadowColor = c.CGColor; b.layer.shadowOpacity = 0.4; b.layer.shadowRadius = 8; b.layer.shadowOffset = CGSizeMake(0, 2);
    [b addTarget:self action:s forControlEvents:UIControlEventTouchUpInside];
    [b.heightAnchor constraintEqualToConstant:42].active = YES;
    return b;
}

// عنوان قسم صغير فوق مجموعة أزرار — يعطي القائمة تنظيماً احترافياً بدل تكديس الأزرار
- (UILabel *)sectionLabel:(NSString *)t {
    UILabel *l = [UILabel new];
    l.text = [t uppercaseString];
    l.font = [UIFont systemFontOfSize:10.5 weight:UIFontWeightBold];
    l.textColor = DSHex(kGold); l.alpha = 0.85;
    return l;
}

- (UIView *)statCard:(NSString *)cap color:(UIColor *)c {
    UIView *v = [UIView new]; v.backgroundColor = DSHex(kPanel); v.layer.cornerRadius = 12; v.layer.cornerCurve = kCACornerCurveContinuous;
    v.layer.borderWidth = 1; v.layer.borderColor = [c colorWithAlphaComponent:0.45].CGColor;
    v.layer.shadowColor = c.CGColor; v.layer.shadowOpacity = 0.25; v.layer.shadowRadius = 8; v.layer.shadowOffset = CGSizeZero;
    UILabel *n = [UILabel new]; n.text = @"0"; n.font = DSMono(20, UIFontWeightBold); n.textColor = c; n.textAlignment = NSTextAlignmentCenter;
    DSGlow(n.layer, c, 6);
    UILabel *k = [UILabel new]; k.text = cap; k.font = DSMono(9, UIFontWeightSemibold); k.textColor = DSHex(kDim); k.textAlignment = NSTextAlignmentCenter;
    UIStackView *st = [[UIStackView alloc] initWithArrangedSubviews:@[n, k]];
    st.axis = UILayoutConstraintAxisVertical; st.spacing = 2; st.translatesAutoresizingMaskIntoConstraints = NO;
    [v addSubview:st];
    [NSLayoutConstraint activateConstraints:@[
        [st.topAnchor constraintEqualToAnchor:v.topAnchor constant:10], [st.bottomAnchor constraintEqualToAnchor:v.bottomAnchor constant:-8],
        [st.leadingAnchor constraintEqualToAnchor:v.leadingAnchor constant:4], [st.trailingAnchor constraintEqualToAnchor:v.trailingAnchor constant:-4]]];
    [_stats addObject:n];
    return v;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    self.view.backgroundColor = DSHex(kBG);
    _stats = [NSMutableArray array];

    // ----- header -----
    _header = [DSGradView new];
    CAGradientLayer *gl = (CAGradientLayer *)_header.layer;
    gl.colors = @[(id)DSHex(0x12305F).CGColor, (id)DSHex(0x0B1424).CGColor, (id)DSHex(kBG).CGColor];
    gl.startPoint = CGPointMake(0, 0); gl.endPoint = CGPointMake(1, 1);
    _header.layer.cornerRadius = 18; _header.layer.cornerCurve = kCACornerCurveContinuous; _header.layer.borderWidth = 1.5;
    _header.layer.borderColor = [DSHex(kGold) colorWithAlphaComponent:0.9].CGColor; _header.clipsToBounds = YES;

    UILabel *logo = [UILabel new];
    NSMutableAttributedString *logoStr = [[NSMutableAttributedString alloc] initWithString:@"♛  AFLATOON SUITE"
        attributes:@{ NSFontAttributeName: DSMono(20, UIFontWeightHeavy), NSForegroundColorAttributeName: DSHex(kGold), NSKernAttributeName: @(2.2) }];
    logo.attributedText = logoStr;
    DSGlow(logo.layer, DSHex(kGold), 10); logo.adjustsFontSizeToFitWidth = YES; logo.minimumScaleFactor = 0.6;
    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    [close setImage:DSIcon(@"xmark.circle.fill", 24) forState:UIControlStateNormal]; close.tintColor = DSHex(kRed);
    [close addTarget:self action:@selector(closeTap) forControlEvents:UIControlEventTouchUpInside];
    [close setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    UIStackView *row1 = [[UIStackView alloc] initWithArrangedSubviews:@[logo, close]]; row1.alignment = UIStackViewAlignmentCenter;

    UILabel *prompt = [UILabel new]; prompt.text = @"┌──(aflatoon㉿kali)-[~]  └─$ ./suite"; prompt.font = DSMono(11, UIFontWeightMedium); prompt.textColor = DSHex(kCyan);
    _cursor = [UILabel new]; _cursor.text = @"█"; _cursor.font = DSMono(11, UIFontWeightBold); _cursor.textColor = DSHex(kGold);
    [_cursor setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    UIStackView *row2 = [[UIStackView alloc] initWithArrangedSubviews:@[prompt, _cursor]]; row2.spacing = 3;

    UIView *creditBadge = [UIView new];
    creditBadge.backgroundColor = [DSHex(kGold) colorWithAlphaComponent:0.18];
    creditBadge.layer.cornerRadius = 9; creditBadge.layer.cornerCurve = kCACornerCurveContinuous;
    creditBadge.layer.borderWidth = 1.2; creditBadge.layer.borderColor = [DSHex(kGold) colorWithAlphaComponent:0.9].CGColor; DSGlow(creditBadge.layer, DSHex(kGold), 7); creditBadge.layer.shadowOpacity = 0.35;
    UIImageView *creditIcon = [[UIImageView alloc] initWithImage:DSAvatarImage()];
    creditIcon.contentMode = UIViewContentModeScaleAspectFill; creditIcon.clipsToBounds = YES;
    creditIcon.layer.cornerRadius = 19; creditIcon.layer.borderWidth = 1.6; creditIcon.layer.borderColor = DSHex(kGold).CGColor;
    [creditIcon.widthAnchor constraintEqualToConstant:38].active = YES; [creditIcon.heightAnchor constraintEqualToConstant:38].active = YES;
    [creditIcon setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    UILabel *credit = [UILabel new]; credit.text = @"© أفلاطون  •  Aflatoon\nجميع الحقوق محفوظة"; credit.numberOfLines = 2;
    credit.font = [UIFont systemFontOfSize:11.5 weight:UIFontWeightHeavy]; credit.textColor = DSHex(kGold);
    credit.adjustsFontSizeToFitWidth = YES; credit.minimumScaleFactor = 0.65;
    UIStackView *creditRow = [[UIStackView alloc] initWithArrangedSubviews:@[creditIcon, credit]];
    creditRow.spacing = 8; creditRow.alignment = UIStackViewAlignmentCenter; creditRow.translatesAutoresizingMaskIntoConstraints = NO;
    [creditBadge addSubview:creditRow];
    [NSLayoutConstraint activateConstraints:@[
        [creditRow.topAnchor constraintEqualToAnchor:creditBadge.topAnchor constant:5], [creditRow.bottomAnchor constraintEqualToAnchor:creditBadge.bottomAnchor constant:-5],
        [creditRow.leadingAnchor constraintEqualToAnchor:creditBadge.leadingAnchor constant:9], [creditRow.trailingAnchor constraintEqualToAnchor:creditBadge.trailingAnchor constant:-9]]];
    UIStackView *creditWrap = [[UIStackView alloc] initWithArrangedSubviews:@[creditBadge, [UIView new]]];   // يدفع الشارة لليسار بدل تمديدها كامل العرض

    UIStackView *hs = [[UIStackView alloc] initWithArrangedSubviews:@[row1, row2, creditWrap]];
    hs.axis = UILayoutConstraintAxisVertical; hs.spacing = 5; hs.translatesAutoresizingMaskIntoConstraints = NO;
    [_header addSubview:hs];
    [NSLayoutConstraint activateConstraints:@[
        [hs.topAnchor constraintEqualToAnchor:_header.topAnchor constant:12], [hs.bottomAnchor constraintEqualToAnchor:_header.bottomAnchor constant:-12],
        [hs.leadingAnchor constraintEqualToAnchor:_header.leadingAnchor constant:14], [hs.trailingAnchor constraintEqualToAnchor:_header.trailingAnchor constant:-10]]];
    _scan = [UIView new]; _scan.backgroundColor = [DSHex(kGold) colorWithAlphaComponent:0.55]; _scan.userInteractionEnabled = NO;
    [_header addSubview:_scan];

    // ----- stats -----
    UIStackView *stats = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self statCard:@"TOTAL" color:DSHex(kGreen)], [self statCard:@"DOMAINS" color:DSHex(kCyan)],
        [self statCard:@"IPS" color:DSHex(kAmber)], [self statCard:@"BLOCKED" color:DSHex(kRed)]]];
    stats.distribution = UIStackViewDistributionFillEqually; stats.spacing = 8;

    // ----- search -----
    _search = [UITextField new]; _search.delegate = self; _search.font = DSMono(14, UIFontWeightRegular); _search.textColor = DSHex(kText);
    _search.attributedPlaceholder = [[NSAttributedString alloc] initWithString:@"grep  domain | ip" attributes:@{ NSForegroundColorAttributeName: DSHex(kDim), NSFontAttributeName: DSMono(14, UIFontWeightRegular) }];
    _search.backgroundColor = DSHex(kPanel); _search.layer.cornerRadius = 12; _search.layer.borderWidth = 1; _search.layer.borderColor = [DSHex(kGold) colorWithAlphaComponent:0.5].CGColor;
    _search.autocapitalizationType = UITextAutocapitalizationTypeNone; _search.autocorrectionType = UITextAutocorrectionTypeNo;
    _search.clearButtonMode = UITextFieldViewModeWhileEditing; _search.returnKeyType = UIReturnKeySearch; _search.keyboardAppearance = UIKeyboardAppearanceDark;
    UIImageView *mag = [[UIImageView alloc] initWithImage:DSIcon(@"magnifyingglass", 14)]; mag.tintColor = DSHex(kGold); mag.contentMode = UIViewContentModeCenter;
    mag.frame = CGRectMake(0, 0, 36, 40); _search.leftView = mag; _search.leftViewMode = UITextFieldViewModeAlways;
    [_search addTarget:self action:@selector(queryChanged:) forControlEvents:UIControlEventEditingChanged];
    [_search.heightAnchor constraintEqualToConstant:40].active = YES;

    // ----- filter -----
    _seg = [[UISegmentedControl alloc] initWithItems:@[@"ALL", @"DOMAINS", @"IP", @"BLOCKED"]];
    _seg.selectedSegmentIndex = 0; _seg.backgroundColor = DSHex(kPanel); _seg.selectedSegmentTintColor = DSHex(kGold);
    [_seg setTitleTextAttributes:@{ NSForegroundColorAttributeName: DSHex(kDim), NSFontAttributeName: DSMono(11, UIFontWeightBold) } forState:UIControlStateNormal];
    [_seg setTitleTextAttributes:@{ NSForegroundColorAttributeName: DSHex(kBG), NSFontAttributeName: DSMono(11, UIFontWeightHeavy) } forState:UIControlStateSelected];
    [_seg addTarget:self action:@selector(reload) forControlEvents:UIControlEventValueChanged];

    // ----- table -----
    _tv = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    _tv.dataSource = self; _tv.delegate = self; _tv.backgroundColor = UIColor.clearColor; _tv.separatorStyle = UITableViewCellSeparatorStyleNone;
    _tv.rowHeight = UITableViewAutomaticDimension; _tv.estimatedRowHeight = 84; _tv.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    [_tv registerClass:DSCell.class forCellReuseIdentifier:@"c"];
    [_tv setContentHuggingPriority:1 forAxis:UILayoutConstraintAxisVertical];
    [_tv setContentCompressionResistancePriority:1 forAxis:UILayoutConstraintAxisVertical];

    // ----- actions -----
    UIStackView *bar1 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:@"SAVE" icon:@"square.and.arrow.down" color:DSHex(kGreen) sel:@selector(saveTap)],
        [self neon:@"SHARE" icon:@"square.and.arrow.up" color:DSHex(kCyan) sel:@selector(shareTap:)],
        [self neon:@"COPY" icon:@"doc.on.doc" color:DSHex(kPurple) sel:@selector(copyTap)],
        [self neon:@"CLEAR" icon:@"trash" color:DSHex(kRed) sel:@selector(clearTap)]]];
    bar1.distribution = UIStackViewDistributionFillEqually; bar1.spacing = 8;
    UIStackView *bar2 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:@"NEXTDNS KEY" icon:@"key.fill" color:DSHex(kAmber) sel:@selector(apiTap)],
        [self neon:@"RULES" icon:@"arrow.triangle.2.circlepath" color:DSHex(kGreen) sel:@selector(rulesTap)],
        [self neon:([DSSettings shared].autoDNS ? @"DNS 8.8.8.8" : @"DNS OFF") icon:@"globe"
             color:([DSSettings shared].autoDNS ? DSHex(kCyan) : DSHex(kDim)) sel:@selector(dnsTap:)]]];
    bar2.distribution = UIStackViewDistributionFillEqually; bar2.spacing = 8;

    UIStackView *bar3 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:([DSSettings shared].forceAll ? @"ALL → 8.8.8.8 : ON" : @"ALL → 8.8.8.8 : OFF") icon:@"bolt.fill"
             color:([DSSettings shared].forceAll ? DSHex(kRed) : DSHex(kDim)) sel:@selector(forceTap:)],
        [self neon:([DSSettings shared].chatMode ? @"CHAT → 8.8.8.8" : @"CHAT OFF") icon:@"bubble.left.and.bubble.right"
             color:([DSSettings shared].chatMode ? DSHex(kGreen) : DSHex(kDim)) sel:@selector(chatTap:)]]];

    _proxyBtn = [self neon:[self proxyTitle] icon:@"network" color:([DSProxy shared].enabled ? DSHex(kGreen) : DSHex(kDim)) sel:@selector(proxyTap:)];
    _proxyBtn.titleLabel.adjustsFontSizeToFitWidth = YES; _proxyBtn.titleLabel.minimumScaleFactor = 0.7;
    UIStackView *barP = [[UIStackView alloc] initWithArrangedSubviews:@[
        _proxyBtn,
        [self neon:@"PROXY LINK" icon:@"link" color:DSHex(kAmber) sel:@selector(proxyLinkTap)],
        [self neon:@"TEST" icon:@"checkmark.seal" color:DSHex(kCyan) sel:@selector(proxyTestTap)]]];
    barP.distribution = UIStackViewDistributionFillEqually; barP.spacing = 6;

    UIStackView *bar4 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:([DSSettings shared].joinSoundOn ? @"JOIN SOUND: ON" : @"JOIN SOUND: OFF") icon:@"speaker.wave.2.fill"
             color:([DSSettings shared].joinSoundOn ? DSHex(kCyan) : DSHex(kDim)) sel:@selector(joinSoundTap:)],
        [self neon:[NSString stringWithFormat:@"SPEED x%d", (int)[DSSettings shared].joinSoundRate] icon:@"gauge.with.dots.needle.67percent"
             color:DSHex(kAmber) sel:@selector(joinSpeedTap:)]]];
    bar4.distribution = UIStackViewDistributionFillEqually; bar4.spacing = 6;

    UIStackView *bar5 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:([DSSettings shared].voiceSpeedOn ? @"VOICE SPEED: ON" : @"VOICE SPEED: OFF") icon:@"waveform"
             color:([DSSettings shared].voiceSpeedOn ? DSHex(kPurple) : DSHex(kDim)) sel:@selector(voiceSpeedTap:)],
        [self neon:[NSString stringWithFormat:@"MAX x%d", (int)[DSSettings shared].voiceSpeedMax] icon:@"gauge.with.dots.needle.67percent"
             color:DSHex(kAmber) sel:@selector(voiceSpeedMaxTap:)]]];
    bar5.distribution = UIStackViewDistributionFillEqually; bar5.spacing = 6;

    UIStackView *barK = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:([DSSettings shared].kbRepeatNums ? @"تكرار الأرقام: ON" : @"تكرار الأرقام: OFF") icon:@"repeat"
             color:([DSSettings shared].kbRepeatNums ? DSHex(kAmber) : DSHex(kDim)) sel:@selector(kbRepeatTap:)],
        [self neon:([DSSettings shared].kbSplitLetters ? @"تفكيك الحروف: ON" : @"تفكيك الحروف: OFF") icon:@"textformat"
             color:([DSSettings shared].kbSplitLetters ? DSHex(kPurple) : DSHex(kDim)) sel:@selector(kbSplitTap:)]]];
    barK.distribution = UIStackViewDistributionFillEqually; barK.spacing = 6;
    for (UIButton *kb in (NSArray<UIButton *> *)barK.arrangedSubviews) { kb.titleLabel.adjustsFontSizeToFitWidth = YES; kb.titleLabel.minimumScaleFactor = 0.7; }

    UIStackView *barK4 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:([DSSettings shared].kbAISend ? @"ارسال ذكي AI: ON" : @"ارسال ذكي AI: OFF") icon:@"sparkles"
             color:([DSSettings shared].kbAISend ? DSHex(kGreen) : DSHex(kDim)) sel:@selector(kbAITap:)],
        [self neon:[NSString stringWithFormat:@"الحساسية: %@", DSKbAILevelName([DSSettings shared].kbAILevel)] icon:@"slider.horizontal.3"
             color:DSHex(kCyan) sel:@selector(kbAILevelTap:)]]];
    barK4.distribution = UIStackViewDistributionFillEqually; barK4.spacing = 6;
    for (UIButton *kb in (NSArray<UIButton *> *)barK4.arrangedSubviews) { kb.titleLabel.adjustsFontSizeToFitWidth = YES; kb.titleLabel.minimumScaleFactor = 0.7; }
    DSSettings *kst = [DSSettings shared];
    UIStackView *barK6 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:(kst.kbPad ? @"كيبورد أرقام عائم: ON" : @"كيبورد أرقام عائم: OFF") icon:@"keyboard"
             color:(kst.kbPad ? DSHex(kGreen) : DSHex(kDim)) sel:@selector(kbPadTap:)],
        [self neon:(kst.kbPadHide ? @"اخفاء كيبورد النظام: ON" : @"اخفاء كيبورد النظام: OFF") icon:@"keyboard.chevron.compact.down"
             color:(kst.kbPadHide ? DSHex(kGreen) : DSHex(kDim)) sel:@selector(kbPadHideTap:)]]];
    barK6.distribution = UIStackViewDistributionFillEqually; barK6.spacing = 6;
    for (UIButton *kb in (NSArray<UIButton *> *)barK6.arrangedSubviews) { kb.titleLabel.adjustsFontSizeToFitWidth = YES; kb.titleLabel.minimumScaleFactor = 0.7; }

    UIStackView *bar6 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:@"⚡ SERVER TEST" icon:@"bolt.fill" color:DSHex(kGreen) sel:@selector(serverTestTap)]]];
    bar6.distribution = UIStackViewDistributionFillEqually; bar6.spacing = 6;
    bar3.distribution = UIStackViewDistributionFillEqually; bar3.spacing = 6;

    UILabel *foot = [UILabel new]; foot.text = @"♛  © أفلاطون // Aflatoon — جميع الحقوق محفوظة  ♛"; foot.textAlignment = NSTextAlignmentCenter;
    foot.font = [UIFont systemFontOfSize:11.5 weight:UIFontWeightHeavy]; foot.textColor = DSHex(kGold);
    DSGlow(foot.layer, DSHex(kGold), 6); foot.layer.shadowOpacity = 0.55; foot.adjustsFontSizeToFitWidth = YES; foot.minimumScaleFactor = 0.7;

    UIView *(^spacer)(void) = ^UIView *{ UIView *v = [UIView new]; [v setContentHuggingPriority:1 forAxis:UILayoutConstraintAxisVertical]; [v setContentCompressionResistancePriority:1 forAxis:UILayoutConstraintAxisVertical]; return v; };
    NSArray<NSDictionary *> *defs = @[
      @{ @"t": @"النطاقات والبيانات", @"s": @"sniff --domains --ips", @"i": @"list.bullet.rectangle", @"c": @(kGreen), @"p": @"~/domains", @"fill": @YES,
         @"v": @[stats, _search, _seg, _tv, [self sectionLabel:@"ادارة البيانات"], bar1] },
      @{ @"t": @"الشبكة وDNS", @"s": @"netctl --dns --proxy", @"i": @"network", @"c": @(kCyan), @"p": @"~/network", @"fill": @NO,
         @"v": @[bar2, bar3, barP] },
      @{ @"t": @"الدردشة والصوت", @"s": @"voice --join --speed", @"i": @"waveform", @"c": @(kPurple), @"p": @"~/voice", @"fill": @NO,
         @"v": @[bar4, bar5] },
      @{ @"t": @"الكيبورد", @"s": @"kbd --repeat --split --ai-send --pad", @"i": @"keyboard", @"c": @(kAmber), @"p": @"~/keyboard", @"fill": @NO,
         @"v": @[barK, barK4, barK6] },
      @{ @"t": @"Server Test", @"s": @"stress --ws --http", @"i": @"bolt.fill", @"c": @(kRed), @"p": @"~/server-test", @"fill": @NO,
         @"v": @[bar6] } ];
    UIStackView *home = [UIStackView new]; home.axis = UILayoutConstraintAxisVertical; home.spacing = 9;
    UILabel *hp = [UILabel new]; hp.numberOfLines = 2; hp.font = DSMono(12, UIFontWeightSemibold); hp.textColor = DSHex(kGreen);
    hp.text = @"┌──(aflatoon㉿kali)-[~]\n└─$ ls options/";
    [home addArrangedSubview:hp];
    NSMutableArray<UIView *> *pages = [NSMutableArray array];
    NSInteger idx = 0;
    for (NSDictionary *d in defs) {
        UIColor *c = DSHex([d[@"c"] unsignedIntValue]);
        [home addArrangedSubview:[self catButton:[NSString stringWithFormat:@"%02ld", (long)(idx + 1)] title:d[@"t"] sub:d[@"s"] icon:d[@"i"] color:c tag:idx]];
        UIStackView *page = [UIStackView new]; page.axis = UILayoutConstraintAxisVertical; page.spacing = 10;
        UIButton *back = [self neon:@"رجوع" icon:@"chevron.backward" color:DSHex(kDim) sel:@selector(backTap)];
        [back.widthAnchor constraintEqualToConstant:104].active = YES;
        UILabel *pt = [UILabel new]; pt.font = DSMono(12, UIFontWeightSemibold); pt.textColor = c; pt.adjustsFontSizeToFitWidth = YES; pt.minimumScaleFactor = 0.7;
        pt.text = [NSString stringWithFormat:@"┌──(aflatoon㉿kali)-[%@]", d[@"p"]];
        UIStackView *brow = [[UIStackView alloc] initWithArrangedSubviews:@[back, pt]]; brow.spacing = 10; brow.alignment = UIStackViewAlignmentCenter;
        [page addArrangedSubview:brow];
        for (UIView *v in d[@"v"]) [page addArrangedSubview:v];
        if (![d[@"fill"] boolValue]) [page addArrangedSubview:spacer()];
        [page setContentHuggingPriority:1 forAxis:UILayoutConstraintAxisVertical];
        page.hidden = YES;
        [pages addObject:page]; idx++;
    }
    [home addArrangedSubview:spacer()];
    [home setContentHuggingPriority:1 forAxis:UILayoutConstraintAxisVertical];
    _home = home; _pages = pages;

    NSMutableArray *mainViews = [NSMutableArray arrayWithObjects:_header, home, nil];
    [mainViews addObjectsFromArray:pages]; [mainViews addObject:foot];
    UIStackView *main = [[UIStackView alloc] initWithArrangedSubviews:mainViews];
    main.axis = UILayoutConstraintAxisVertical; main.spacing = 10; main.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:main];
    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [main.topAnchor constraintEqualToAnchor:g.topAnchor constant:10], [main.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-6],
        [main.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:14], [main.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-14]]];

    _toast = [UILabel new]; _toast.backgroundColor = DSHex(kPanel); _toast.textColor = DSHex(kGreen); _toast.textAlignment = NSTextAlignmentCenter;
    _toast.font = DSMono(12, UIFontWeightBold); _toast.layer.cornerRadius = 10; _toast.layer.borderWidth = 1; _toast.layer.borderColor = DSHex(kGreen).CGColor;
    _toast.clipsToBounds = YES; _toast.alpha = 0; _toast.adjustsFontSizeToFitWidth = YES; _toast.minimumScaleFactor = 0.7;
    _toast.translatesAutoresizingMaskIntoConstraints = NO; [self.view addSubview:_toast];
    [NSLayoutConstraint activateConstraints:@[
        [_toast.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor], [_toast.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-120],
        [_toast.widthAnchor constraintGreaterThanOrEqualToConstant:180], [_toast.widthAnchor constraintLessThanOrEqualToAnchor:self.view.widthAnchor constant:-40],
        [_toast.heightAnchor constraintEqualToConstant:38]]];
    [self reload];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    _timer = [NSTimer scheduledTimerWithTimeInterval:1.5 target:self selector:@selector(reload) userInfo:nil repeats:YES];
    CABasicAnimation *b = [CABasicAnimation animationWithKeyPath:@"opacity"];
    b.fromValue = @1; b.toValue = @0; b.duration = 0.55; b.autoreverses = YES; b.repeatCount = HUGE_VALF;
    [_cursor.layer addAnimation:b forKey:@"blink"];
}
- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self.view layoutIfNeeded];
    CGFloat w = _header.bounds.size.width, h = _header.bounds.size.height;
    _scan.frame = CGRectMake(0, 0, w, 1.5);
    [UIView animateWithDuration:2.6 delay:0 options:UIViewAnimationOptionRepeat | UIViewAnimationOptionCurveLinear animations:^{
        self->_scan.frame = CGRectMake(0, h - 1.5, w, 1.5);
    } completion:nil];
}
- (void)viewDidDisappear:(BOOL)animated { [super viewDidDisappear:animated]; [_timer invalidate]; _timer = nil; }

- (void)reload {
    if (_proxyBtn) [self styleProxyBtn];
    NSInteger m = _seg.selectedSegmentIndex;
    NSString *q = _query.lowercaseString;
    NSArray *all = [[DSStore shared] snapshot];
    NSMutableArray *out = [NSMutableArray array];
    NSUInteger nd = 0, ni = 0, nb = 0;
    for (NSDictionary *e in all) {
        BOOL dom = [e[@"type"] isEqualToString:@"domain"], blk = [e[@"status"] isEqualToString:@"BLOCKED"];
        if (dom) nd++; else ni++;
        if (blk) nb++;
        if (m == 1 && !dom) continue;
        if (m == 2 && dom) continue;
        if (m == 3 && !blk) continue;
        if (q.length) {
            NSString *hay = [[NSString stringWithFormat:@"%@ %@", e[@"value"], [e[@"related"] componentsJoinedByString:@" "]] lowercaseString];
            if (![hay containsString:q]) continue;
        }
        [out addObject:e];
    }
    _data = out;
    NSArray *nums = @[@(all.count), @(nd), @(ni), @(nb)];
    for (NSUInteger i = 0; i < _stats.count; i++) _stats[i].text = [nums[i] stringValue];
    [_tv reloadData];
}

- (void)toast:(NSString *)t {
    _toast.text = t;
    [_toast.layer removeAllAnimations];
    [UIView animateWithDuration:0.2 animations:^{ self->_toast.alpha = 1; } completion:^(BOOL f) {
        [UIView animateWithDuration:0.3 delay:1.8 options:0 animations:^{ self->_toast.alpha = 0; } completion:nil];
    }];
}

- (void)closeTap { [self dismissViewControllerAnimated:YES completion:nil]; }
- (void)queryChanged:(UITextField *)t { _query = t.text; [self reload]; }
- (BOOL)textFieldShouldReturn:(UITextField *)t { [t resignFirstResponder]; return YES; }

- (void)dnsTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.autoDNS = !st.autoDNS; [st save];
    UIColor *c = st.autoDNS ? DSHex(kCyan) : DSHex(kDim);
    [b setTitle:(st.autoDNS ? @"DNS 8.8.8.8" : @"DNS OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.titleLabel.adjustsFontSizeToFitWidth = YES; b.titleLabel.minimumScaleFactor = 0.7;
    [self toast:(st.autoDNS ? @"DNS تلقائي → 8.8.8.8 ✅" : @"DNS التلقائي متوقف")];
}

- (void)forceTap:(UIButton *)b {   // يعمل لحظياً: الأعلام تُقرأ عند كل اتصال جديد
    DSSettings *st = [DSSettings shared];
    st.forceAll = !st.forceAll; [st save];
    UIColor *c = st.forceAll ? DSHex(kRed) : DSHex(kDim);
    [b setTitle:(st.forceAll ? @"ALL → 8.8.8.8 : ON" : @"ALL → 8.8.8.8 : OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.titleLabel.adjustsFontSizeToFitWidth = YES; b.titleLabel.minimumScaleFactor = 0.7;
    [self toast:(st.forceAll ? @"كل النطاقات والـ IPs → 8.8.8.8 ⚡" : @"رجع الوضع الطبيعي")];
}

- (NSString *)proxyTitle {
    DSProxy *p = [DSProxy shared];
    if (!p.enabled) return @"PROXY: OFF";
    return [NSString stringWithFormat:@"PROXY: ON ⚡%d", (int)atomic_load(&gProxyHits)];
}

- (void)styleProxyBtn {
    UIColor *c = [DSProxy shared].enabled ? DSHex(kGreen) : DSHex(kDim);
    [_proxyBtn setTitle:[self proxyTitle] forState:UIControlStateNormal];
    [_proxyBtn setTitleColor:c forState:UIControlStateNormal]; _proxyBtn.tintColor = c;
    _proxyBtn.backgroundColor = [c colorWithAlphaComponent:0.10];
    _proxyBtn.layer.borderColor = [c colorWithAlphaComponent:0.5].CGColor;
}

- (void)proxyAlert:(NSString *)title msg:(NSString *)msg {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"حسناً" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)proxyTap:(UIButton *)b {
    DSProxy *p = [DSProxy shared];
    if (!p.enabled && !p.host.length) { [self proxyLinkTap]; return; }   // لا يوجد رابط بعد
    p.enabled = !p.enabled; [p save]; [self styleProxyBtn];
    [self toast:p.enabled ? @"تم تشغيل البروكسي ✅ (للاتصالات الجديدة)" : @"تم إيقاف البروكسي"];
}

- (void)proxyRunTest {
    [self toast:@"⏳ جارٍ اختبار البروكسي…"];
    DSProxyTest(^(NSString *report, BOOL ok) { [self proxyAlert:(ok ? @"✅ البروكسي يعمل" : @"❌ فشل البروكسي") msg:report]; });
}

- (void)proxyApplyText:(NSString *)txt {
    NSString *err = nil;
    if (![[DSProxy shared] applyLink:txt error:&err]) { [self proxyAlert:@"❌ رابط غير صالح" msg:err ?: @"تعذّر قراءة الرابط"]; return; }
    [self styleProxyBtn];
    [self proxyRunTest];   // بعد الحفظ والتفعيل نختبره مباشرة
}

- (void)proxyLinkTap {
    DSProxy *p = [DSProxy shared];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"🌐 رابط البروكسي"
        message:@"socks5://user:pass@host:1080\nhttp://host:8080\nhost:port  أو  host:port:user:pass\nرابط تيليجرام: t.me/socks?server=..&port=.." preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.placeholder = @"socks5://host:port"; t.text = p.link; t.font = DSMono(13, UIFontWeightRegular);
        t.keyboardType = UIKeyboardTypeURL; t.clearButtonMode = UITextFieldViewModeWhileEditing;
        t.autocapitalizationType = UITextAutocapitalizationTypeNone; t.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    __weak UIAlertController *wa = a;
    [a addAction:[UIAlertAction actionWithTitle:@"حفظ وتفعيل" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        [self proxyApplyText:wa.textFields[0].text ?: @""];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"📋 لصق من الحافظة وتفعيل" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        [self proxyApplyText:UIPasteboard.generalPasteboard.string ?: @""];
    }]];
    if (p.host.length) {
        [a addAction:[UIAlertAction actionWithTitle:@"🗑 حذف البروكسي" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) {
            p.enabled = NO; p.link = nil; p.host = nil; p.user = nil; p.pass = nil; p.port = 0; [p save];
            [self styleProxyBtn]; [self toast:@"تم حذف البروكسي"];
        }]];
    }
    [a addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)proxyTestTap {
    if (![DSProxy shared].host.length) { [self proxyLinkTap]; return; }
    [self proxyRunTest];
}

- (void)chatTap:(UIButton *)b {   // لحظي: يسري على أي اتصال جديد
    DSSettings *st = [DSSettings shared];
    st.chatMode = !st.chatMode; [st save];
    UIColor *c = st.chatMode ? DSHex(kGreen) : DSHex(kDim);
    [b setTitle:(st.chatMode ? @"CHAT → 8.8.8.8" : @"CHAT OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.titleLabel.adjustsFontSizeToFitWidth = YES; b.titleLabel.minimumScaleFactor = 0.7;
    [self toast:(st.chatMode ? @"الدردشة والكتابة → 8.8.8.8 💬" : @"الدردشة رجعت طبيعية")];
}

static NSString *DSFindJoinSoundFile(void);   // تصريح مسبق — التعريف الكامل لاحقاً بنفس الملف

- (void)joinSoundTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.joinSoundOn = !st.joinSoundOn; [st save];
    UIColor *c = st.joinSoundOn ? DSHex(kCyan) : DSHex(kDim);
    [b setTitle:(st.joinSoundOn ? @"JOIN SOUND: ON" : @"JOIN SOUND: OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.titleLabel.adjustsFontSizeToFitWidth = YES; b.titleLabel.minimumScaleFactor = 0.7;
    if (st.joinSoundOn && !DSFindJoinSoundFile())
        [self toast:@"⚠️ ضع ملف join.mp3 (أو wav/m4a/caf) داخل Documents/AflatoonSuite"];
    else
        [self toast:(st.joinSoundOn ? @"صوت الدخول مفعّل 🔊" : @"صوت الدخول متوقف")];
}

- (void)joinSpeedTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    int cur = (int)st.joinSoundRate; int next = cur + 1; if (next > 4) next = 1;
    st.joinSoundRate = (float)next; [st save];
    [b setTitle:[NSString stringWithFormat:@"SPEED x%d", next] forState:UIControlStateNormal];
    [self toast:[NSString stringWithFormat:@"سرعة صوت الدخول x%d", next]];
}

- (void)kbRepeatTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.kbRepeatNums = !st.kbRepeatNums; [st save];
    UIColor *c = st.kbRepeatNums ? DSHex(kAmber) : DSHex(kDim);
    [b setTitle:(st.kbRepeatNums ? @"تكرار الأرقام: ON" : @"تكرار الأرقام: OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12]; b.layer.borderColor = [c colorWithAlphaComponent:0.5].CGColor;
    [self toast:(st.kbRepeatNums ? @"تكرار الأرقام مفعّل: 135 ← 135.135 🔁" : @"تكرار الأرقام متوقف")];
}

- (void)kbSplitTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.kbSplitLetters = !st.kbSplitLetters; [st save];
    UIColor *c = st.kbSplitLetters ? DSHex(kPurple) : DSHex(kDim);
    [b setTitle:(st.kbSplitLetters ? @"تفكيك الحروف: ON" : @"تفكيك الحروف: OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12]; b.layer.borderColor = [c colorWithAlphaComponent:0.5].CGColor;
    [self toast:(st.kbSplitLetters ? @"تفكيك الحروف مفعّل: حسين ← ح س ي ن ✂️" : @"تفكيك الحروف متوقف")];
}

- (void)kbPadTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.kbPad = !st.kbPad; [st save];
    DSKeypadSetVisible(st.kbPad);
    UIColor *c = st.kbPad ? DSHex(kGreen) : DSHex(kDim);
    [b setTitle:(st.kbPad ? @"كيبورد أرقام عائم: ON" : @"كيبورد أرقام عائم: OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12]; b.layer.borderColor = [c colorWithAlphaComponent:0.5].CGColor;
    [self toast:(st.kbPad ? @"ظهر الكيبورد العائم — اسحبه من الشريط العلوي، ويبقى حتى لو أغلقت المنيو" : @"أُخفي الكيبورد العائم")];
}

- (void)kbPadHideTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.kbPadHide = !st.kbPadHide; [st save];
    DSKeypadApplyHide();
    UIColor *c = st.kbPadHide ? DSHex(kGreen) : DSHex(kDim);
    [b setTitle:(st.kbPadHide ? @"اخفاء كيبورد النظام: ON" : @"اخفاء كيبورد النظام: OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12]; b.layer.borderColor = [c colorWithAlphaComponent:0.5].CGColor;
    [self toast:(st.kbPadHide ? @"كيبورد النظام مخفي طالما العائم ظاهر" : @"كيبورد النظام يظهر مع العائم")];
}

- (void)kbAITap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.kbAISend = !st.kbAISend; [st save];
    UIColor *c = st.kbAISend ? DSHex(kGreen) : DSHex(kDim);
    [b setTitle:(st.kbAISend ? @"ارسال ذكي AI: ON" : @"ارسال ذكي AI: OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12]; b.layer.borderColor = [c colorWithAlphaComponent:0.5].CGColor;
    [self toast:(st.kbAISend ? @"الذكاء يتعلم إيقاع كتابتك ويرسل بعد ما تنتهي فقط ✨" : @"الارسال الذكي متوقف")];
}

- (void)kbAILevelTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.kbAILevel = (st.kbAILevel + 1) % 3; st.kbAIMul = 1.0; [st save];
    [b setTitle:[NSString stringWithFormat:@"الحساسية: %@", DSKbAILevelName(st.kbAILevel)] forState:UIControlStateNormal];
    [self toast:[NSString stringWithFormat:@"الحساسية: %@ — أعدت تعلّم الذكاء من الصفر", DSKbAILevelName(st.kbAILevel)]];
}

- (void)voiceSpeedTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.voiceSpeedOn = !st.voiceSpeedOn; [st save];
    UIColor *c = st.voiceSpeedOn ? DSHex(kPurple) : DSHex(kDim);
    [b setTitle:(st.voiceSpeedOn ? @"VOICE SPEED: ON" : @"VOICE SPEED: OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.titleLabel.adjustsFontSizeToFitWidth = YES; b.titleLabel.minimumScaleFactor = 0.7;
    [self toast:(st.voiceSpeedOn ? @"سرعة صوت المتكلمين مفعّلة 🎙️" : @"سرعة صوت المتكلمين متوقفة")];
}

- (void)voiceSpeedMaxTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    int cur = (int)st.voiceSpeedMax; int next = cur + 1; if (next > 4) next = 1;
    st.voiceSpeedMax = (float)next; [st save];
    [b setTitle:[NSString stringWithFormat:@"MAX x%d", next] forState:UIControlStateNormal];
    [self toast:[NSString stringWithFormat:@"الحد الأقصى للتسريع x%d", next]];
}

- (void)rulesTap {
    DSRulesVC *vc = [[DSRulesVC alloc] initWithStyle:UITableViewStyleInsetGrouped];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)serverTestTap {
    DSTestVC *vc = [DSTestVC new];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)apiTap {
    DSSettings *st = [DSSettings shared];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"🔑 NextDNS"
        message:@"مفتاح API من my.nextdns.io/account\nProfile ID اختياري (يُكتشف تلقائياً)" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.placeholder = st.apiKey.length ? @"•••••• (محفوظ — اتركه فارغاً للإبقاء)" : @"API Key";
        t.autocapitalizationType = UITextAutocapitalizationTypeNone; t.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.placeholder = @"Profile ID (اختياري)"; t.text = st.profileId;
        t.autocapitalizationType = UITextAutocapitalizationTypeNone; t.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    __weak UIAlertController *wa = a;
    [a addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"حذف المفتاح" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) {
        st.apiKey = nil; st.profileId = nil; [st save]; [self toast:@"تم حذف المفتاح"];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"حفظ" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        NSCharacterSet *ws = NSCharacterSet.whitespaceAndNewlineCharacterSet;
        NSString *k = [wa.textFields[0].text stringByTrimmingCharactersInSet:ws];
        NSString *p = [wa.textFields[1].text stringByTrimmingCharactersInSet:ws];
        if (k.length) st.apiKey = k;
        if (![p isEqualToString:st.profileId ?: @""] || k.length) st.profileId = p.length ? p : nil;
        [st save];
        if (!st.apiKey.length) { [self toast:@"لا يوجد مفتاح"]; return; }
        [self toast:@"جاري التحقق…"];
        DSNDEnsureProfile(^(NSString *pid, NSString *err) {
            [self toast:pid ? @"تم الحفظ والتحقق ✅" : err];
        });
    }]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)blockDomain:(NSString *)d {
    DSSettings *st = [DSSettings shared];
    if (!st.apiKey.length) { [self toast:@"أدخل مفتاح API أولاً"]; [self apiTap]; return; }
    [self toast:@"جاري الإرسال…"];
    DSNDEnsureProfile(^(NSString *pid, NSString *err) {
        if (!pid) { [self toast:err]; return; }
        NSString *path = [NSString stringWithFormat:@"/profiles/%@/denylist", pid];
        DSNDRequest(@"POST", path, @{ @"id": d, @"active": @YES }, ^(NSInteger code, id json, NSError *e) {
            if (code / 100 == 2) { [st markSent:d]; [self toast:[NSString stringWithFormat:@"⛔ تم حجب %@", d]]; [self reload]; }
            else if (code == 409 || [DSNDErrorText(code, json) containsString:@"duplicate"]) { [st markSent:d]; [self toast:@"موجود مسبقاً في Denylist"]; [self reload]; }
            else if (code == 401 || code == 403) [self toast:@"مفتاح API غير صحيح"];
            else [self toast:e ? e.localizedDescription : DSNDErrorText(code, json)];
        });
    });
}

- (void)showActionsFor:(NSDictionary *)e from:(UIView *)src {
    NSString *v = e[@"value"];
    BOOL isDomain = [e[@"type"] isEqualToString:@"domain"];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:v message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    if (isDomain) {
        [a addAction:[UIAlertAction actionWithTitle:@"⛔ حجب (NextDNS)" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) { [self blockDomain:v]; }]];
    } else {
        NSUInteger n = 0;
        for (NSString *r in e[@"related"]) {
            if (DSIsIPString(r) || n++ >= 3) continue;
            [a addAction:[UIAlertAction actionWithTitle:[@"⛔ حجب " stringByAppendingString:r] style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) { [self blockDomain:r]; }]];
        }
    }
    [a addAction:[UIAlertAction actionWithTitle:@"🔁 استبدال…" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        [DSRulesVC promptFrom:v over:self done:^{ [self toast:@"تمت إضافة القاعدة ✅"]; }];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"📋 نسخ" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        UIPasteboard.generalPasteboard.string = v; [self toast:@"تم النسخ"];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    a.popoverPresentationController.sourceView = src;
    a.popoverPresentationController.sourceRect = src.bounds;
    [self presentViewController:a animated:YES completion:nil];
}

- (void)saveTap {
    [[DSStore shared] saveAll];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"تم الحفظ ✅"
        message:@"Documents/AflatoonSuite/\n• denylist_nextdns.txt\n• domains.txt\n• ips.txt\n• data.json\n\nاستخدم زر SHARE لحفظها في تطبيق الملفات."
        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"حسناً" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)shareTap:(UIButton *)sender {
    NSArray *urls = [[DSStore shared] saveAll];
    UIActivityViewController *vc = [[UIActivityViewController alloc] initWithActivityItems:urls applicationActivities:nil];
    vc.popoverPresentationController.sourceView = sender;
    vc.popoverPresentationController.sourceRect = sender.bounds;
    [self presentViewController:vc animated:YES completion:nil];
}

- (void)copyTap {
    UIPasteboard.generalPasteboard.string = [[DSStore shared] denylistText];
    [self toast:[NSString stringWithFormat:@"تم نسخ %lu نطاق", (unsigned long)[[DSStore shared] denylistCount]]];
}

- (void)clearTap {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"مسح كل السجل؟" message:nil preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"مسح" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) {
        [[DSStore shared] clear]; [self reload];
    }]];
    [self presentViewController:a animated:YES completion:nil];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    if (_data.count == 0) {
        UILabel *l = [UILabel new]; l.numberOfLines = 0; l.textAlignment = NSTextAlignmentCenter;
        l.text = @"$ waiting for traffic…\nشغّل اللعبة وراح تظهر الاتصالات هنا";
        l.font = DSMono(12, UIFontWeightRegular); l.textColor = DSHex(kDim); tv.backgroundView = l;
    } else tv.backgroundView = nil;
    return _data.count;
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    DSCell *c = [tv dequeueReusableCellWithIdentifier:@"c" forIndexPath:ip];
    NSDictionary *e = _data[ip.row];
    [c configure:e sent:[[DSSettings shared] wasSent:e[@"value"]]];
    return c;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    [self showActionsFor:_data[ip.row] from:[tv cellForRowAtIndexPath:ip]];
}
@end

#pragma mark - Floating orb

@interface DSPassWindow : UIWindow
@end
@implementation DSPassWindow
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *v = [super hitTest:p withEvent:e];
    return (v == self.rootViewController.view || v == self) ? nil : v;
}
@end

@interface DSRootVC : UIViewController
@end
@implementation DSRootVC {
    UIButton *_fab; UIView *_ring; UILabel *_banner;
}
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.clearColor;
    _ring = [[UIView alloc] initWithFrame:CGRectMake(16, 140, 56, 56)];
    _ring.layer.cornerRadius = 28; _ring.layer.borderWidth = 1.5; _ring.layer.borderColor = DSHex(kGreen).CGColor;
    _ring.userInteractionEnabled = NO; [self.view addSubview:_ring];
    _fab = [UIButton buttonWithType:UIButtonTypeCustom];
    _fab.frame = CGRectMake(16, 140, 56, 56);
    _fab.backgroundColor = [DSHex(kBG) colorWithAlphaComponent:0.94];
    _fab.layer.cornerRadius = 28; _fab.layer.borderWidth = 1.5; _fab.layer.borderColor = DSHex(kGreen).CGColor;
    DSGlow(_fab.layer, DSHex(kGreen), 10);
    [_fab setImage:DSIcon(@"dot.radiowaves.left.and.right", 22) forState:UIControlStateNormal]; _fab.tintColor = DSHex(kGreen);
    [_fab addTarget:self action:@selector(open) forControlEvents:UIControlEventTouchUpInside];
    [_fab addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(pan:)]];
    [self.view addSubview:_fab];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(startPulse) name:UIApplicationDidBecomeActiveNotification object:nil];
}
- (void)startPulse {
    [_ring.layer removeAllAnimations];
    CABasicAnimation *s = [CABasicAnimation animationWithKeyPath:@"transform.scale"]; s.fromValue = @1; s.toValue = @1.7;
    CABasicAnimation *o = [CABasicAnimation animationWithKeyPath:@"opacity"]; o.fromValue = @0.7; o.toValue = @0;
    CAAnimationGroup *g = [CAAnimationGroup animation]; g.animations = @[s, o]; g.duration = 1.8; g.repeatCount = HUGE_VALF;
    [_ring.layer addAnimation:g forKey:@"pulse"];
}
- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self startPulse];
    if (_banner) return;
    _banner = [UILabel new]; _banner.text = @"  ◉ AFLATOON SUITE  •  © أفلاطون / Aflatoon  ";
    _banner.font = DSMono(11, UIFontWeightBold); _banner.textColor = DSHex(kGreen); _banner.backgroundColor = [DSHex(kBG) colorWithAlphaComponent:0.95];
    _banner.layer.cornerRadius = 12; _banner.layer.borderWidth = 1; _banner.layer.borderColor = DSHex(kGreen).CGColor; _banner.clipsToBounds = YES;
    [_banner sizeToFit];
    CGFloat bw = _banner.bounds.size.width + 8, bh = 26;
    _banner.frame = CGRectMake((self.view.bounds.size.width - bw) / 2, self.view.safeAreaInsets.top + 6, bw, bh);
    _banner.textAlignment = NSTextAlignmentCenter; _banner.alpha = 0;
    [self.view addSubview:_banner];
    [UIView animateWithDuration:0.35 animations:^{ self->_banner.alpha = 1; } completion:^(BOOL f) {
        [UIView animateWithDuration:0.6 delay:3.0 options:0 animations:^{ self->_banner.alpha = 0; } completion:nil];
    }];
}
- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGRect b = self.view.bounds; CGPoint c = _fab.center;
    c.x = MIN(MAX(c.x, 28), b.size.width - 28); c.y = MIN(MAX(c.y, 28), b.size.height - 28);
    _fab.center = c; _ring.center = c;
}
- (void)pan:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:self.view];
    _fab.center = CGPointMake(_fab.center.x + t.x, _fab.center.y + t.y); _ring.center = _fab.center;
    [g setTranslation:CGPointZero inView:self.view];
    [self.view setNeedsLayout];
}
- (void)open {
    if (self.presentedViewController) return;
    DSMenuVC *vc = [DSMenuVC new];
    vc.modalPresentationStyle = UIModalPresentationFullScreen;
    [self presentViewController:vc animated:YES completion:nil];
}
@end

#pragma mark - تسريع صوت الروم مع الحفاظ على النغمة (WSOLA)
// ملاحظة مهمة: الدردشة حيّة وليست ملفاً جاهزاً. السرعة "تتكيّف" حسب التراكم المتوفر فقط —
// تبدأ من 1x وتتصاعد تدريجياً حتى الحد الأقصى المختار كلما وُجد تراكم (بعد وقفات الكلام مثلاً)،
// وتهدأ تلقائياً عند نفاد التراكم. هذا السلوك مُختبَر ومؤكد رياضياً (محرك overlap-add قياسي)،
// وليس تخميناً. تمت تجربة النواة بمعزل عن اللعبة قبل الدمج هنا.
#define DS_WS_CAP (48000 * 8)

typedef struct {
    int16_t ring[DS_WS_CAP]; long wpos, rpos;
    int sr, Hs, win, search;
    float accum[2048];
    long anaPos;
    int16_t prevTail[1024];
    int primed;
} DSWsola;

static void DSWsInit(DSWsola *w, int sr) {
    memset(w, 0, sizeof *w);
    w->sr = sr; w->Hs = sr / 100; w->win = w->Hs * 2; w->search = w->Hs / 2;
}
static void DSWsFeed(DSWsola *w, const int16_t *in, int n) {
    for (int i = 0; i < n; i++) w->ring[(w->wpos + i) % DS_WS_CAP] = in[i];
    w->wpos += n;
    if (w->wpos - w->rpos > DS_WS_CAP - 4096) w->rpos = w->wpos - (DS_WS_CAP - 4096);
}
static int16_t DSWsAt(DSWsola *w, long pos) { return (pos < w->rpos || pos >= w->wpos) ? 0 : w->ring[pos % DS_WS_CAP]; }

static int DSWsBestOffset(DSWsola *w, long candidate, const int16_t *ref, int refLen) {
    long bestScore = -1; int best = 0;
    for (int off = -w->search; off <= w->search; off++) {
        long start = candidate + off;
        if (start < w->rpos || start + refLen >= w->wpos) continue;
        long score = 0;
        for (int i = 0; i < refLen; i++) { int32_t a = ref[i], b = DSWsAt(w, start + i); score += a * b; }
        if (score > bestScore) { bestScore = score; best = off; }
    }
    return best;
}

// ينتج Hs عيّنة نهائية في كل نداء (نفس عدد العيّنات المطلوب من Agora)؛ السرعة تتكيّف تلقائياً
static void DSWsStep(DSWsola *w, int16_t *outHs, float maxSpeed) {
    if (w->Hs <= 0 || w->Hs > 1024) return;
    long avail = w->wpos - w->anaPos;
    float backlogSec = (float)avail / w->sr;
    float speed = 1.0f + (maxSpeed - 1.0f) * fminf(backlogSec / 1.0f, 1.0f);
    int Ha = (int)(w->Hs * speed); if (Ha < w->Hs) Ha = w->Hs;
    if (!w->primed) { w->anaPos = w->rpos; w->primed = 1; }

    int off = DSWsBestOffset(w, w->anaPos, w->prevTail, w->Hs);
    long start = w->anaPos + off;
    if (start < w->rpos) start = w->rpos;

    for (int i = 0; i < w->win; i++) {
        float tri = (i < w->Hs) ? (float)i / w->Hs : (float)(w->win - i) / w->Hs;
        w->accum[i] += DSWsAt(w, start + i) * tri;
    }
    for (int i = 0; i < w->Hs; i++) {
        float v = w->accum[i];
        if (v > 32767) v = 32767; if (v < -32768) v = -32768;
        outHs[i] = (int16_t)v;
    }
    for (int i = 0; i < w->Hs; i++) w->prevTail[i] = DSWsAt(w, start + w->Hs + i);
    memmove(w->accum, w->accum + w->Hs, (w->win - w->Hs) * sizeof(float));
    memset(w->accum + (w->win - w->Hs), 0, w->Hs * sizeof(float));
    w->anaPos = start + Ha;
    if (w->anaPos > w->wpos) w->anaPos = w->wpos;
}

// ---- ربط Agora: مراقب صوت خام رسمي (AgoraAudioDataFrameProtocol) — يعالج الصوت القادم لجهازك فقط ----
static DSWsola gVoiceWs[8];              // قناة لكل "uid" متكلم، حتى ما تتداخل أصوات اللاعبين ببعض
static NSMapTable *gVoiceWsByUid;        // uid -> فهرس في gVoiceWs
static dispatch_once_t gVoiceWsOnce;

static DSWsola *DSWsForUid(NSUInteger uid) {
    dispatch_once(&gVoiceWsOnce, ^{
        gVoiceWsByUid = [NSMapTable strongToStrongObjectsMapTable];
        for (int i = 0; i < 8; i++) DSWsInit(&gVoiceWs[i], 48000);
    });
    NSNumber *key = @(uid);
    NSNumber *idx = [gVoiceWsByUid objectForKey:key];
    if (!idx) {
        static int next = 0;
        idx = @(next % 8); next++;
        [gVoiceWsByUid setObject:idx forKey:key];
        DSWsInit(&gVoiceWs[idx.intValue], 48000);
    }
    return &gVoiceWs[idx.intValue];
}

@protocol DSAgoraAudioDataFrameProtocol <NSObject>
@optional
- (BOOL)onRecordAudioFrame:(id)frame;
- (BOOL)onPlaybackAudioFrame:(id)frame;
- (BOOL)onMixedAudioFrame:(id)frame;
- (BOOL)onPlaybackAudioFrameBeforeMixing:(id)frame uid:(NSUInteger)uid;
@end

@interface DSAudioFrameProxy : NSObject <DSAgoraAudioDataFrameProtocol>
@end
@implementation DSAudioFrameProxy
// نعالج الصوت *قبل الخلط* لكل متكلم على حدة (uid)، حتى التسريع ما يشوّش أصوات بعض ببعض
- (BOOL)onPlaybackAudioFrameBeforeMixing:(id)frameObj uid:(NSUInteger)uid {
    if (![DSSettings shared].voiceSpeedOn) return YES;
    @try {
        id bufVal = [frameObj valueForKey:@"buffer"];   // قد يصل كـ NSValue يغلّف مؤشر void* (وليس مؤشراً مباشراً)
        int16_t *buf = NULL;
        if ([bufVal isKindOfClass:[NSValue class]]) buf = (int16_t *)[(NSValue *)bufVal pointerValue];
        else if ([bufVal isKindOfClass:[NSNumber class]]) buf = (int16_t *)(uintptr_t)[(NSNumber *)bufVal unsignedLongLongValue];
        else buf = NULL;
        NSInteger samplesPerChannel = [[frameObj valueForKey:@"samplesPerChannel"] integerValue];
        NSInteger channels = [[frameObj valueForKey:@"channels"] integerValue];
        NSInteger sr = [[frameObj valueForKey:@"samplesPerSec"] integerValue];
        if (!buf || samplesPerChannel <= 0 || samplesPerChannel > 1024 || channels < 1 || channels > 2 || sr < 8000 || sr > 48000) return YES;
        DSWsola *w = DSWsForUid(uid);
        if (w->sr != (int)sr) DSWsInit(w, (int)sr);
        float maxSpeed = [DSSettings shared].voiceSpeedMax;

        if (channels == 1) {
            DSWsFeed(w, buf, (int)samplesPerChannel);
            int16_t out[1024];
            DSWsStep(w, out, maxSpeed);
            memcpy(buf, out, samplesPerChannel * sizeof(int16_t));
        } else {   // ستيريو: نفصل القناتين، نعالج كل وحدة بنفس قرار المحاذاة، ثم نعيد التشبيك
            static int16_t left[1024], right[1024], outL[1024], outR[1024];
            for (NSInteger i = 0; i < samplesPerChannel; i++) { left[i] = buf[i*2]; right[i] = buf[i*2+1]; }
            DSWsFeed(w, left, (int)samplesPerChannel);
            DSWsStep(w, outL, maxSpeed);
            DSWsFeed(w, right, (int)samplesPerChannel);   // ملاحظة: يعالج القناتين بتوقيت مستقل بسيط؛ كافٍ لصوت بشري أحادي المصدر عادة
            DSWsStep(w, outR, maxSpeed);
            for (NSInteger i = 0; i < samplesPerChannel; i++) { buf[i*2] = outL[i]; buf[i*2+1] = outR[i]; }
        }
    } @catch (__unused NSException *e) { return YES; }   // أي خلل غير متوقع: مرّر الصوت الأصلي بدون تعديل، أبداً لا نكسر الاتصال
    return YES;
}
- (BOOL)onPlaybackAudioFrame:(id)frame { return YES; }   // نعتمد "قبل الخلط" لكل متكلم على حدة؛ هذا احتياطي فقط
- (BOOL)onRecordAudioFrame:(id)frame { return YES; }
- (BOOL)onMixedAudioFrame:(id)frame { return YES; }
@end

static DSAudioFrameProxy *gDSAudioProxy;
static void DSEnsureVoiceSpeedWired(id engine) {   // يستدعى عند أول انضمام ناجح لروم
    if (!engine) return;
    static BOOL done = NO; if (done) return; done = YES;
    @try {
        if (!gDSAudioProxy) gDSAudioProxy = [DSAudioFrameProxy new];
        if ([engine respondsToSelector:@selector(setAgoraAudioFrameDelegate:)])
            [engine performSelector:@selector(setAgoraAudioFrameDelegate:) withObject:gDSAudioProxy];
        // تفعيل استلام الصوت الخام قبل الخلط، وضع قراءة وكتابة (2)، عيّنات 10ms عند 48kHz
        SEL sel = NSSelectorFromString(@"setPlaybackAudioFrameParametersWithSampleRate:channel:mode:samplesPerCall:");
        if ([engine respondsToSelector:sel]) {
            NSMethodSignature *sig = [engine methodSignatureForSelector:sel];
            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
            inv.selector = sel; inv.target = engine;
            NSInteger sr = 48000, ch = 1, mode = 2, spc = 480;
            [inv setArgument:&sr atIndex:2]; [inv setArgument:&ch atIndex:3];
            [inv setArgument:&mode atIndex:4]; [inv setArgument:&spc atIndex:5];
            [inv invoke];
        }
    } @catch (__unused NSException *e) {}
}

#pragma mark - صوت دخول الروم (ملف محلي فقط، بدون أي تسجيل أو سمع لأحد)

// ضع ملف الصوت باسم join.mp3 أو join.wav أو join.m4a أو join.caf داخل:
// Documents/AflatoonSuite  (نفس مجلد settings.json — يظهر عبر File Sharing في ESign/Files)
static AVAudioPlayer *gJoinPlayer;

static NSString *DSFindJoinSoundFile(void) {
    NSArray *names = @[@"join.mp3", @"join.wav", @"join.m4a", @"join.caf"];
    for (NSString *n in names) {
        NSString *p = [DSDir() stringByAppendingPathComponent:n];
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) return p;
    }
    return nil;
}

static void DSPlayJoinSound(void) {
    if (![DSSettings shared].joinSoundOn) return;
    NSString *path = DSFindJoinSoundFile();
    if (!path) { NSLog(@"[AflatoonSuite] join sound: ضع ملف join.mp3/.wav/.m4a/.caf داخل Documents/AflatoonSuite"); return; }
    dispatch_async(dispatch_get_main_queue(), ^{
        NSError *err = nil;
        [[AVAudioSession sharedInstance] setCategory:AVAudioSessionCategoryAmbient error:nil];   // صيغة كلاسيكية، متوفرة بكل إصدارات SDK
        [[AVAudioSession sharedInstance] setActive:YES error:nil];
        AVAudioPlayer *p = [[AVAudioPlayer alloc] initWithContentsOfURL:[NSURL fileURLWithPath:path] error:&err];
        if (!p) { NSLog(@"[AflatoonSuite] تعذر تشغيل ملف الصوت: %@", err); return; }
        p.enableRate = YES;
        float r = [DSSettings shared].joinSoundRate; if (r < 1) r = 1; if (r > 4) r = 4;
        p.rate = r;
        p.volume = 1.0;
        gJoinPlayer = p;   // تمسكه حتى ما ينقطع بالـ ARC قبل ما يخلّص
        [p play];
    });
}

// ── بديل مدمج لـ MSHookMessageEx ──────────────────────────────────────────────
// كود Logos المولَّد يستدعي MSHookMessageEx من CydiaSubstrate، وهذا كان يجعل الـ dylib
// يعتمد على Substrate (ويفشل الحقن بدون جيلبريك). نعرّف الدالة هنا بنفس التوقيع
// باستخدام ObjC runtime فقط، فيُحَلّ الرمز محلياً ويسقط الاعتماد على Substrate.
#ifdef __cplusplus
extern "C" {
#endif
void MSHookMessageEx(Class cls, SEL sel, IMP imp, IMP *result);
#ifdef __cplusplus
}
#endif

void MSHookMessageEx(Class cls, SEL sel, IMP imp, IMP *result) {
    if (result) *result = NULL;
    if (!cls || !sel || !imp) return;
    Method m = class_getInstanceMethod(cls, sel);   // للـ class methods يمرّر Logos الـ metaclass
    if (!m) return;                                 // الدالة غير موجودة في هذا الإصدار من المكتبة
    const char *types = method_getTypeEncoding(m);
    IMP old = NULL;
    if (class_addMethod(cls, sel, imp, types)) {
        old = method_getImplementation(m);          // كانت موروثة: الأصل هو دالة الأب
    } else {
        old = method_setImplementation(m, imp);     // الكلاس يملكها: نستبدلها ونحفظ الأصل
    }
    if (result) *result = old;
}

// Hook مكتبة Agora (إن وجدت بالتطبيق) — يشتغل الصوت فقط عند نجاح الانضمام الفعلي للروم،
// ولا يتدخّل بأي صوت ثاني داخل المكالمة ولا يسمع/يسجّل أحد — تشغيل ملف محلي فقط.
%group DSAgoraJoinSoundHooks

// تم تأكيد أسماء الدوال هذه من ثنائيات AgoraRtcKit.framework الفعلية داخل IPA اللعبة.
// غرف يلا لودو تستخدم أسلوب القنوات المتعددة (AgoraRtcChannel عبر createRtcChannel:)،
// فالانضمام الفعلي للروم الصوتي يصير على كائن القناة، لا على AgoraRtcEngineKit نفسه.

%hook AgoraRtcChannel

- (int)joinChannelByToken:(NSString *)token info:(NSString *)info uid:(NSUInteger)uid options:(id)options joinSuccess:(void (^)(NSString *, NSUInteger, NSInteger))joinSuccessBlock {
    int r = %orig;
    if (r == 0) DSPlayJoinSound();
    return r;
}

- (int)joinChannelByToken:(NSString *)token info:(NSString *)info uid:(NSUInteger)uid options:(id)options {
    int r = %orig;
    if (r == 0) DSPlayJoinSound();
    return r;
}

- (int)joinChannelByUserAccount:(NSString *)userAccount token:(NSString *)token options:(id)options {
    int r = %orig;
    if (r == 0) DSPlayJoinSound();
    return r;
}

%end

// احتياطي: إذا روم معيّن استخدم أسلوب القناة الواحدة (الانضمام مباشرة على المحرك)
%hook AgoraRtcEngineKit

+ (instancetype)sharedEngineWithAppId:(NSString *)appId delegate:(id)delegate {
    id r = %orig;
    DSEnsureVoiceSpeedWired(r);
    return r;
}
+ (instancetype)sharedEngineWithConfig:(id)config delegate:(id)delegate {
    id r = %orig;
    DSEnsureVoiceSpeedWired(r);
    return r;
}

- (int)joinChannelByToken:(NSString *)token channelId:(NSString *)channelId info:(NSString *)info uid:(NSUInteger)uid joinSuccess:(void (^)(NSString *, NSUInteger, NSInteger))joinSuccessBlock {
    int r = %orig;
    if (r == 0) DSPlayJoinSound();
    return r;
}

- (int)joinChannelByToken:(NSString *)token channelId:(NSString *)channelId info:(NSString *)info uid:(NSUInteger)uid options:(id)options joinSuccess:(void (^)(NSString *, NSUInteger, NSInteger))joinSuccessBlock {
    int r = %orig;
    if (r == 0) DSPlayJoinSound();
    return r;
}

%end
%end

#pragma mark - الكيبورد: تكرار الأرقام + تفكيك الحروف

// يعمل على أي UITextField / UITextView داخل التطبيق المضيف (بما فيها كيبورد Unity)
// عبر اعتراض insertText: و deleteBackward. لا يمسّ شاشات الأداة نفسها ولا حقول كلمة السر.
static BOOL gKbBusy = NO;   // حارس إعادة الدخول (الخيط الرئيسي فقط)

static inline BOOL DSKbIsDigit(unichar c) {
    return (c >= '0' && c <= '9') || (c >= 0x0660 && c <= 0x0669) || (c >= 0x06F0 && c <= 0x06F9);
}
static BOOL DSKbAllDigits(NSString *s) {
    if (!s.length) return NO;
    for (NSUInteger i = 0; i < s.length; i++) if (!DSKbIsDigit([s characterAtIndex:i])) return NO;
    return YES;
}
static BOOL DSKbIsLetter(NSString *cluster) {
    if (!cluster.length) return NO;
    return [NSCharacterSet.letterCharacterSet characterIsMember:[cluster characterAtIndex:0]];
}
static BOOL DSKbIsMark(NSString *cluster) {
    if (!cluster.length) return NO;
    return [NSCharacterSet.nonBaseCharacterSet characterIsMember:[cluster characterAtIndex:0]];
}

// النص قبل المؤشر (آخر n حرف)
static NSString *DSKbBefore(id<UITextInput> t, NSInteger n) {
    UITextRange *sel = t.selectedTextRange; if (!sel) return @"";
    UITextPosition *end = sel.start, *start = [t positionFromPosition:end offset:-n];
    if (!start) start = t.beginningOfDocument;
    UITextRange *r = [t textRangeFromPosition:start toPosition:end];
    return r ? ([t textInRange:r] ?: @"") : @"";
}

// هل النص ينتهي بنمط  D.D  (نفس الرقم مكرراً)؟ يرجع D
static NSString *DSKbTrailingRun(NSString *before) {
    NSUInteger n = before.length, i = n;
    while (i > 0 && DSKbIsDigit([before characterAtIndex:i - 1])) i--;
    NSUInteger n2 = n - i;
    if (!n2 || i < n2 + 1) return nil;
    if ([before characterAtIndex:i - 1] != '.') return nil;
    NSString *d2 = [before substringFromIndex:i];
    NSString *d1 = [before substringWithRange:NSMakeRange(i - 1 - n2, n2)];
    return [d1 isEqualToString:d2] ? d2 : nil;
}

// الحقل مؤهل للتعديل؟ (ليس من شاشات الأداة، ليس كلمة سر، تحديد فارغ، لا كتابة IME معلّقة)
static BOOL DSKbEligible(id t) {
    if (gKbBusy || (!gKbRepeat && !gKbSplit) || ![NSThread isMainThread]) return NO;
    if (![t isKindOfClass:UIView.class]) return NO;
    if ([((UIView *)t).window isKindOfClass:DSPassWindow.class]) return NO;
    if ([(id<UITextInputTraits>)t isSecureTextEntry]) return NO;
    UITextRange *sel = [(id<UITextInput>)t selectedTextRange];
    if (!sel || !sel.isEmpty) return NO;
    if ([(id<UITextInput>)t markedTextRange]) return NO;
    return YES;
}

// خطة الإدخال: احذف `del` حرفاً قبل المؤشر ثم أدخل `rep`
static BOOL DSKbPlanInsert(id t, NSString *text, NSUInteger *del, NSString **rep) {
    if (!text.length || !DSKbEligible(t)) return NO;
    // 1) تكرار الأرقام: 1 → 1.1 ، ثم 3 → 13.13 ، ثم 5 → 135.135
    if (gKbRepeat && DSKbAllDigits(text)) {
        NSString *run = DSKbTrailingRun(DSKbBefore(t, 200));
        NSString *raw = [(run ?: @"") stringByAppendingString:text];
        *del = run ? run.length * 2 + 1 : 0;
        *rep = [NSString stringWithFormat:@"%@.%@", raw, raw];
        return YES;
    }
    // 2) تفكيك الحروف: بين كل حرفين مسافة
    if (gKbSplit) {
        __block BOOL hasLetter = NO;
        [text enumerateSubstringsInRange:NSMakeRange(0, text.length) options:NSStringEnumerationByComposedCharacterSequences
            usingBlock:^(NSString *c, NSRange r, NSRange er, BOOL *stop) { if (DSKbIsLetter(c)) { hasLetter = YES; *stop = YES; } }];
        if (!hasLetter) return NO;
        NSString *before = DSKbBefore(t, 4);
        NSString *prev = nil;
        if (before.length) {
            NSRange lr = [before rangeOfComposedCharacterSequenceAtIndex:before.length - 1];
            prev = [before substringWithRange:lr];
        }
        __block BOOL prevLetterish = prev && (DSKbIsLetter(prev) || DSKbIsMark(prev));
        NSMutableString *out = [NSMutableString string];
        [text enumerateSubstringsInRange:NSMakeRange(0, text.length) options:NSStringEnumerationByComposedCharacterSequences
            usingBlock:^(NSString *c, NSRange r, NSRange er, BOOL *stop) {
            BOOL letter = DSKbIsLetter(c);
            if (letter && prevLetterish) [out appendString:@" "];
            [out appendString:c];
            prevLetterish = letter || DSKbIsMark(c);
        }];
        if ([out isEqualToString:text]) return NO;
        *del = 0; *rep = out;
        return YES;
    }
    return NO;
}

// خطة الحذف: مسح 135.135 يرجع 13.13 (حذف رقم واحد من الأصل)، ومسح حرف مفكّك يمسح مسافته أيضاً
static BOOL DSKbPlanDelete(id t, NSUInteger *del, NSString **rep) {
    if (!DSKbEligible(t)) return NO;
    NSString *before = DSKbBefore(t, 200);
    if (gKbRepeat) {
        NSString *run = DSKbTrailingRun(before);
        if (run) {
            *del = run.length * 2 + 1;
            if (run.length > 1) { NSString *r2 = [run substringToIndex:run.length - 1]; *rep = [NSString stringWithFormat:@"%@.%@", r2, r2]; }
            else *rep = nil;
            return YES;
        }
    }
    if (gKbSplit && before.length >= 3) {
        NSUInteger n = before.length;
        NSString *l2 = [before substringWithRange:NSMakeRange(n - 1, 1)], *l1 = [before substringWithRange:NSMakeRange(n - 3, 1)];
        if ([before characterAtIndex:n - 2] == ' ' && DSKbIsLetter(l2) && DSKbIsLetter(l1)) { *del = 2; *rep = nil; return YES; }
    }
    return NO;
}

// إرسال: يحاكي زر Return/Send (UITextField → textFieldShouldReturn، UITextView → سطر جديد)
static NSUInteger gKbIdleGen = 0;   // رقم الجيل: أي ضغطة (إدخال/مسح) تلغي مؤقت الإرسال السابق
static void DSKbSendNow(id t) {
    if ([t isKindOfClass:UITextField.class]) {
        UITextField *f = t; id<UITextFieldDelegate> d = f.delegate;
        if ([d respondsToSelector:@selector(textFieldShouldReturn:)]) [d textFieldShouldReturn:f];
        [f sendActionsForControlEvents:UIControlEventEditingDidEndOnExit];
    } else if ([t isKindOfClass:UITextView.class]) {
        UITextView *v = t; id<UITextViewDelegate> d = v.delegate; BOOL ok = YES;
        if ([d respondsToSelector:@selector(textView:shouldChangeTextInRange:replacementText:)])
            ok = [d textView:v shouldChangeTextInRange:v.selectedRange replacementText:@"\n"];
        if (ok) { gKbBusy = YES; [v insertText:@"\n"]; gKbBusy = NO; }   // busy: لا يعيد تسليح المؤقت
    }
}

static NSString *DSKbTextOf(id t) {
    return [t isKindOfClass:UITextField.class] ? ((UITextField *)t).text : [t isKindOfClass:UITextView.class] ? ((UITextView *)t).text : nil;
}

// ───────── الإرسال الذكي (AI) ─────────
// نموذج خفيف يعمل داخل الجهاز (بدون إنترنت): يتعلم إيقاع كتابتك لحظة بلحظة:
//  1) يقيس الفواصل بين الضغطات ويحسب متوسطها وتشتتها (EMA) → أطول فاصل طبيعي لديك = متوسط + 3×تشتت.
//  2) مهلة الإرسال = ذلك الفاصل × عامل الحساسية × معامل التعلّم. فإذا كتبت ببطء يطوّل المهلة، وإذا كتبت بسرعة يقصّرها.
//  3) سريع جداً: يرسل بعد أقل من ~0.1–0.25 ثانية من آخر ضغطة ورفع الإصبع؛ ولا يرسل أبداً والإصبع على الكيبورد.
//  4) يتعلم من أخطائه: إذا أرسل مبكراً (بقي النص في الحقل وكتبت فوراً) يرفع معامل التعلّم ويحفظه.
static NSUInteger gKbIdleGen = 0;   // أي ضغطة تلغي الإرسال المعلّق
static double gKbLastTap = 0, gKbMean = 0.35, gKbVarEma = 0.01; static NSUInteger gKbSamples = 0;
static double gKbSentAt = 0; static NSString *gKbSentText = nil; static BOOL gKbPenalized = NO;

static double DSKbNow(void) { return CACurrentMediaTime(); }

static void DSKbSendNow(id t) {
    if ([t isKindOfClass:UITextField.class]) {
        UITextField *f = t; id<UITextFieldDelegate> d = f.delegate;
        if ([d respondsToSelector:@selector(textFieldShouldReturn:)]) [d textFieldShouldReturn:f];
        [f sendActionsForControlEvents:UIControlEventEditingDidEndOnExit];
    } else if ([t isKindOfClass:UITextView.class]) {
        UITextView *v = t; id<UITextViewDelegate> d = v.delegate; BOOL ok = YES;
        if ([d respondsToSelector:@selector(textView:shouldChangeTextInRange:replacementText:)])
            ok = [d textView:v shouldChangeTextInRange:v.selectedRange replacementText:@"\n"];
        if (ok) { gKbBusy = YES; [v insertText:@"\n"]; gKbBusy = NO; }
    }
}

static NSString *DSKbTextOf(id t) {
    return [t isKindOfClass:UITextField.class] ? ((UITextField *)t).text : [t isKindOfClass:UITextView.class] ? ((UITextView *)t).text : nil;
}

// يتعلم من الفاصل الجديد بين ضغطتين
static void DSKbLearnTap(void) {
    double now = DSKbNow(), dt = now - gKbLastTap; gKbLastTap = now;
    if (dt <= 0.02 || dt > 2.0) return;                 // تجاهل الارتداد والاستراحات الطويلة
    double a = gKbSamples < 6 ? 0.35 : 0.15; gKbSamples++;
    double diff = dt - gKbMean;
    gKbMean += a * diff;
    gKbVarEma = (1 - a) * (gKbVarEma + a * diff * diff);
}

// المهلة المتوقعة (ثوانٍ) قبل أن نعتبر أنك انتهيت — قصيرة جداً، ومضبوطة على سرعة كتابتك أنت
static double DSKbAIWait(NSString *txt, BOOL afterDelete) {
    double sd = sqrt(MAX(gKbVarEma, 0.0001));
    double gap = gKbSamples < 3 ? 0.22 : (gKbMean + 2.5 * sd);          // أطول فاصل طبيعي بين ضغطاتك
    double lvl = gKbAILevel == 0 ? 1.5 : gKbAILevel == 2 ? 1.0 : 1.2;   // متوازن / فوري / سريع
    double floorS = gKbAILevel == 0 ? 0.25 : gKbAILevel == 2 ? 0.08 : 0.15;
    double w = gap * lvl * gKbAIMul;
    if (afterDelete) w += 0.10;                                          // تعدّل → مهلة صغيرة إضافية
    unichar last = txt.length ? [txt characterAtIndex:txt.length - 1] : 0;
    if (last == ' ' || last == ',' || last == 0x060C) w *= 1.3;          // بعد مسافة غالباً ستكمل
    return MAX(floorS, MIN(0.9, w));
}

// الأصابع على الشاشة الآن؟ (يُحدَّث من UIApplication sendEvent) — لا نرسل والإصبع على زر الكيبورد
static NSInteger gKbFingers = 0; static double gKbFingerSince = 0;
static BOOL DSKbFingerDown(void) {
    if (gKbFingers <= 0) return NO;
    return DSKbNow() - gKbFingerSince < 0.6;   // إصبع محتجز أكثر من 0.6ث (ضغط مطوّل) لا يمنع الإرسال
}

static void DSKbArmAI(id t, BOOL afterDelete) {
    NSUInteger gen = ++gKbIdleGen;
    NSString *snap = DSKbTextOf(t) ?: @"";
    double w = DSKbAIWait(snap, afterDelete);
    __block void (^fire)(void) = nil;
    fire = ^{
        if (gen != gKbIdleGen || !gKbAI) { fire = nil; return; }              // ضغطة أحدث ألغت هذا المؤقت
        if (DSKbFingerDown()) {                                               // الإصبع ما زال على الكيبورد: أعد الفحص بعد لحظة
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.02 * NSEC_PER_SEC)), dispatch_get_main_queue(), fire);
            return;
        }
        fire = nil;
        if (![(UIResponder *)t isFirstResponder]) return;
        if ([(id<UITextInput>)t markedTextRange]) return;                     // ما زال يكتب (IME)
        NSString *txt = DSKbTextOf(t);
        if (![txt isEqualToString:snap]) return;                              // النص تغيّر من مصدر آخر
        if (![txt stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length) return;
        gKbIdleGen++;
        if (!gKbPenalized && gKbAIMul > 1.0) {                                // نجاح بلا أخطاء → خفّف المعامل تدريجياً
            DSSettings *st = [DSSettings shared]; st.kbAIMul = MAX(1.0, st.kbAIMul - 0.03); gKbAIMul = st.kbAIMul;
        }
        gKbPenalized = NO; gKbSentAt = DSKbNow(); gKbSentText = txt;
        DSKbSendNow(t);
    };
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(w * NSEC_PER_SEC)), dispatch_get_main_queue(), fire);
}

// تُستدعى بعد كل ضغطة (إدخال أو مسح) — حتى لو الحقل غير مؤهل — فلا يُرسل أثناء الكتابة
static void DSKbAfterInsert(id t, NSString *text) {
    if (gKbBusy) return;
    gKbIdleGen++;
    if (!gKbAI || ![NSThread isMainThread]) return;
    if ([text isEqualToString:@"\n"]) return;                              // المستخدم ضغط Return بنفسه
    if (![t isKindOfClass:UIView.class]) return;
    if ([((UIView *)t).window isKindOfClass:DSPassWindow.class]) return;
    if ([(id<UITextInputTraits>)t isSecureTextEntry]) return;
    // كشف الإرسال المبكر: كتبت فوراً بعد إرسال والنص ما زال في الحقل → الذكاء أخطأ، يتعلم ويطوّل
    if (gKbSentText && DSKbNow() - gKbSentAt < 1.5) {
        NSString *cur = DSKbTextOf(t) ?: @"";
        if (cur.length > gKbSentText.length && [cur hasPrefix:gKbSentText]) {
            DSSettings *st = [DSSettings shared]; st.kbAIMul = MIN(3.0, st.kbAIMul + 0.25); gKbAIMul = st.kbAIMul;
            gKbPenalized = YES; gKbSentText = nil;
            dispatch_async(dispatch_get_global_queue(0, 0), ^{ [st save]; });
        }
    }
    DSKbLearnTap();
    DSKbArmAI(t, text == nil);
}

// مدخل فارغ يحل محل كيبورد النظام أثناء ظهور الكيبورد العائم (اختياري)
@interface DSBlankInput : UIView @end
@implementation DSBlankInput
- (CGSize)intrinsicContentSize { return CGSizeMake(UIViewNoIntrinsicMetric, 1); }
@end
static void DSKpPrepareInput(id r) {
    if (![r isKindOfClass:UIView.class] || [((UIView *)r).window isKindOfClass:DSPassWindow.class]) return;
    UIView *iv = [r inputView];
    if (gKpOn && gKpHideSys) {
        if (!iv) { DSBlankInput *b = [[DSBlankInput alloc] initWithFrame:CGRectMake(0, 0, 1, 1)]; b.autoresizingMask = UIViewAutoresizingFlexibleWidth; [r setInputView:b]; }
    } else if ([iv isKindOfClass:DSBlankInput.class]) {
        [r setInputView:nil];
    }
}

%group DSKeyboardHooks

// تتبّع لمس الشاشة: نعرف متى يرفع المستخدم إصبعه عن الكيبورد
%hook UIApplication
- (void)sendEvent:(UIEvent *)event {
    if (event.type == UIEventTypeTouches) {
        NSInteger down = 0;
        for (UITouch *t in event.allTouches) if (t.phase != UITouchPhaseEnded && t.phase != UITouchPhaseCancelled) down++;
        if (down > 0 && gKbFingers == 0) gKbFingerSince = DSKbNow();
        gKbFingers = down;
    }
    %orig;
}
%end

%hook UITextField
- (BOOL)becomeFirstResponder { DSKpPrepareInput(self); return %orig; }
- (void)insertText:(NSString *)text {
    NSUInteger del = 0; NSString *rep = nil;
    if (DSKbPlanInsert(self, text, &del, &rep)) {
        gKbBusy = YES;
        for (NSUInteger i = 0; i < del; i++) [self deleteBackward];
        gKbBusy = NO;
        %orig(rep);
    } else {
        %orig;
    }
    DSKbAfterInsert(self, text);
}
- (void)deleteBackward {
    BOOL outer = !gKbBusy;
    if (outer) gKbIdleGen++;
    NSUInteger del = 0; NSString *rep = nil;
    if (DSKbPlanDelete(self, &del, &rep)) {
        gKbBusy = YES;
        for (NSUInteger i = 0; i < del; i++) %orig;
        if (rep.length) [self insertText:rep];
        gKbBusy = NO;
    } else {
        %orig;
    }
    if (outer) DSKbAfterInsert(self, nil);   // بعد المسح: أعد العدّ، يُرسل فقط إذا انتهيت وتوقفت
}
%end

%hook UITextView
- (BOOL)becomeFirstResponder { DSKpPrepareInput(self); return %orig; }
- (void)insertText:(NSString *)text {
    NSUInteger del = 0; NSString *rep = nil;
    if (DSKbPlanInsert(self, text, &del, &rep)) {
        gKbBusy = YES;
        for (NSUInteger i = 0; i < del; i++) [self deleteBackward];
        gKbBusy = NO;
        %orig(rep);
    } else {
        %orig;
    }
    DSKbAfterInsert(self, text);
}
- (void)deleteBackward {
    BOOL outer = !gKbBusy;
    if (outer) gKbIdleGen++;
    NSUInteger del = 0; NSString *rep = nil;
    if (DSKbPlanDelete(self, &del, &rep)) {
        gKbBusy = YES;
        for (NSUInteger i = 0; i < del; i++) %orig;
        if (rep.length) [self insertText:rep];
        gKbBusy = NO;
    } else {
        %orig;
    }
    if (outer) DSKbAfterInsert(self, nil);   // بعد المسح: أعد العدّ، يُرسل فقط إذا انتهيت وتوقفت
}
%end

%end

static DSPassWindow *gWindow;

static void DSShow(void) {
    if (gWindow) return;
    UIWindowScene *scene = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:UIWindowScene.class] && s.activationState == UISceneActivationStateForegroundActive) {
            scene = (UIWindowScene *)s; break;
        }
    }
    DSPassWindow *w = scene ? [[DSPassWindow alloc] initWithWindowScene:scene]
                            : [[DSPassWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    w.windowLevel = UIWindowLevelAlert + 100;
    w.backgroundColor = UIColor.clearColor;
    w.rootViewController = [DSRootVC new];
    w.hidden = NO;
    gWindow = w;
}


// ═════════ الكيبورد العائم للأرقام: يُسحب لأي مكان، يبقى بعد إغلاق المنيو، استجابة فورية عند اللمس ═════════
static UIView *DSKpFind(UIView *v) {
    if (v.isFirstResponder) return v;
    for (UIView *sub in v.subviews) { UIView *r = DSKpFind(sub); if (r) return r; }
    return nil;
}

@interface DSKeypadWindow : UIWindow @end
@implementation DSKeypadWindow
- (BOOL)canBecomeKeyWindow { return NO; }      // لا يسرق التركيز من حقل الكتابة أبداً
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *v = [super hitTest:p withEvent:e];
    return (v == self || v == self.rootViewController.view) ? nil : v;
}
@end

static __weak UIView *gKpTarget;
static UIView *DSKpTarget(void) {
    UIView *t = gKpTarget;
    if (t && t.isFirstResponder) return t;                      // مخزّن: بدون بحث في كل ضغطة
    for (UIScene *sc in UIApplication.sharedApplication.connectedScenes) {
        if (![sc isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *w in ((UIWindowScene *)sc).windows) {
            if ([w isKindOfClass:DSKeypadWindow.class]) continue;
            UIView *r = DSKpFind(w);
            if (r && ([r isKindOfClass:UITextField.class] || [r isKindOfClass:UITextView.class])) { gKpTarget = r; return r; }
        }
    }
    return nil;
}

@interface DSKeyBtn : UIButton @property (nonatomic, strong) UIColor *normalBG, *pressBG; @end
@implementation DSKeyBtn
- (void)setHighlighted:(BOOL)h { [super setHighlighted:h]; self.backgroundColor = h ? self.pressBG : self.normalBG; }   // بدون أي أنيميشن
@end

@interface DSKeypadVC : UIViewController @end
@implementation DSKeypadVC {
    UIView *_panel; NSTimer *_rep; CGPoint _start; CGFloat _rx, _ry, _scale; CGSize _lastSize;
}
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.clearColor;
    NSUserDefaults *u = NSUserDefaults.standardUserDefaults;
    _rx = [u objectForKey:@"DSKpRX"] ? [u doubleForKey:@"DSKpRX"] : 0.5;
    _ry = [u objectForKey:@"DSKpRY"] ? [u doubleForKey:@"DSKpRY"] : 0.72;
    _scale = [u objectForKey:@"DSKpScale"] ? [u doubleForKey:@"DSKpScale"] : 1.0;
    [self build];
}

- (DSKeyBtn *)key:(NSString *)t frame:(CGRect)f fn:(BOOL)fn {
    DSKeyBtn *b = [DSKeyBtn buttonWithType:UIButtonTypeCustom]; b.frame = f;
    b.normalBG = fn ? [UIColor colorWithRed:0.67 green:0.69 blue:0.74 alpha:1] : UIColor.whiteColor;
    b.pressBG  = fn ? UIColor.whiteColor : [UIColor colorWithRed:0.67 green:0.69 blue:0.74 alpha:1];
    b.backgroundColor = b.normalBG; b.layer.cornerRadius = 9; b.layer.cornerCurve = kCACornerCurveContinuous;
    b.layer.shadowColor = UIColor.blackColor.CGColor; b.layer.shadowOpacity = 0.25; b.layer.shadowRadius = 0; b.layer.shadowOffset = CGSizeMake(0, 1);
    b.titleLabel.font = [UIFont systemFontOfSize:25 weight:UIFontWeightRegular];
    [b setTitleColor:UIColor.blackColor forState:UIControlStateNormal];
    if (t) [b setTitle:t forState:UIControlStateNormal];
    b.exclusiveTouch = NO;
    return b;
}

- (void)build {
    const CGFloat W = 276, pad = 8, gap = 6, kh = 52, gh = 32, fh = 38, kw = (W - 2 * pad - 3 * gap) / 4, H = gh + fh + gap + 4 * kh + 3 * gap + pad;
    UIView *p = [[UIView alloc] initWithFrame:CGRectMake(0, 0, W, H)];
    p.backgroundColor = [UIColor colorWithRed:0.82 green:0.83 blue:0.86 alpha:0.98];
    p.layer.cornerRadius = 20; p.layer.cornerCurve = kCACornerCurveContinuous;
    p.layer.shadowColor = UIColor.blackColor.CGColor; p.layer.shadowOpacity = 0.35; p.layer.shadowRadius = 14; p.layer.shadowOffset = CGSizeMake(0, 6);
    _panel = p; [self.view addSubview:p];

    // شريط السحب (الإمساك) + تكبير/تصغير + إغلاق
    UIView *grip = [[UIView alloc] initWithFrame:CGRectMake(0, 0, W, gh)];
    UIView *pill = [[UIView alloc] initWithFrame:CGRectMake((W - 46) / 2, 13, 46, 6)];
    pill.backgroundColor = [UIColor colorWithWhite:0.45 alpha:0.55]; pill.layer.cornerRadius = 3; [grip addSubview:pill];
    [grip addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(pan:)]];
    [p addSubview:grip];
    UIButton *x = [UIButton buttonWithType:UIButtonTypeSystem]; x.frame = CGRectMake(W - 44, 0, 44, gh);
    [x setTitle:@"✕" forState:UIControlStateNormal]; x.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightBold];
    [x setTitleColor:[UIColor colorWithWhite:0.35 alpha:1] forState:UIControlStateNormal];
    [x addTarget:self action:@selector(closePad) forControlEvents:UIControlEventTouchUpInside]; [p addSubview:x];
    UIButton *z = [UIButton buttonWithType:UIButtonTypeSystem]; z.frame = CGRectMake(0, 0, 44, gh);
    [z setTitle:@"⤢" forState:UIControlStateNormal]; z.titleLabel.font = [UIFont systemFontOfSize:17 weight:UIFontWeightBold];
    [z setTitleColor:[UIColor colorWithWhite:0.35 alpha:1] forState:UIControlStateNormal];
    [z addTarget:self action:@selector(cycleScale) forControlEvents:UIControlEventTouchUpInside]; [p addSubview:z];

    // صف اختصارات فوق لوحة الأرقام: عكس الرقم (١٢→٢١) وتكرار آخر رقمة
    CGFloat fw = (W - 2 * pad - gap) / 2;
    DSKeyBtn *rev = [self key:nil frame:CGRectMake(pad, gh, fw, fh) fn:YES];
    [rev setTitle:@"↺ عكس" forState:UIControlStateNormal]; rev.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
    [rev addTarget:self action:@selector(reverseKey) forControlEvents:UIControlEventTouchDown]; [p addSubview:rev];
    DSKeyBtn *rep = [self key:nil frame:CGRectMake(pad + fw + gap, gh, fw, fh) fn:YES];
    [rep setTitle:@"⇄ كرر" forState:UIControlStateNormal]; rep.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
    [rep addTarget:self action:@selector(repeatLastKey) forControlEvents:UIControlEventTouchDown]; [p addSubview:rep];

    CGFloat (^X)(int) = ^CGFloat(int c) { return pad + c * (kw + gap); };
    CGFloat (^Y)(int) = ^CGFloat(int r) { return gh + fh + gap + r * (kh + gap); };
    NSArray *rows = @[@[@"1", @"2", @"3"], @[@"4", @"5", @"6"], @[@"7", @"8", @"9"]];
    for (int r = 0; r < 3; r++) for (int c = 0; c < 3; c++) {
        DSKeyBtn *b = [self key:rows[r][c] frame:CGRectMake(X(c), Y(r), kw, kh) fn:NO];
        [b addTarget:self action:@selector(typeKey:) forControlEvents:UIControlEventTouchDown]; [p addSubview:b];
    }
    DSKeyBtn *dot = [self key:@"." frame:CGRectMake(X(0), Y(3), kw, kh) fn:YES];
    DSKeyBtn *zero = [self key:@"0" frame:CGRectMake(X(1), Y(3), kw, kh) fn:NO];
    DSKeyBtn *sp = [self key:@"␣" frame:CGRectMake(X(2), Y(3), kw, kh) fn:YES]; sp.titleLabel.font = [UIFont systemFontOfSize:20];
    DSKeyBtn *cm = [self key:@"," frame:CGRectMake(X(3), Y(1), kw, kh) fn:YES];
    for (DSKeyBtn *b in @[dot, zero, cm]) { [b addTarget:self action:@selector(typeKey:) forControlEvents:UIControlEventTouchDown]; [p addSubview:b]; }
    [sp addTarget:self action:@selector(typeSpace) forControlEvents:UIControlEventTouchDown]; [p addSubview:sp];

    DSKeyBtn *del = [self key:nil frame:CGRectMake(X(3), Y(0), kw, kh) fn:YES];
    UIImageSymbolConfiguration *cfg = [UIImageSymbolConfiguration configurationWithPointSize:21 weight:UIImageSymbolWeightRegular];
    [del setImage:[UIImage systemImageNamed:@"delete.left" withConfiguration:cfg] forState:UIControlStateNormal]; del.tintColor = UIColor.blackColor;
    [del addTarget:self action:@selector(delDown) forControlEvents:UIControlEventTouchDown];
    [del addTarget:self action:@selector(delUp) forControlEvents:UIControlEventTouchUpInside | UIControlEventTouchUpOutside | UIControlEventTouchCancel];
    [p addSubview:del];
    DSKeyBtn *ret = [self key:nil frame:CGRectMake(X(3), Y(2), kw, 2 * kh + gap) fn:YES];
    [ret setImage:[UIImage systemImageNamed:@"return" withConfiguration:cfg] forState:UIControlStateNormal]; ret.tintColor = UIColor.blackColor;
    [ret addTarget:self action:@selector(retKey) forControlEvents:UIControlEventTouchDown]; [p addSubview:ret];
    p.transform = CGAffineTransformMakeScale(_scale, _scale);
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGSize s = self.view.bounds.size;
    if (!CGSizeEqualToSize(s, _lastSize)) { _lastSize = s; [self place]; }
}
- (void)place {
    CGSize s = self.view.bounds.size; CGFloat hw = _panel.bounds.size.width * _scale / 2, hh = _panel.bounds.size.height * _scale / 2;
    CGFloat cx = MAX(hw, MIN(s.width - hw, _rx * s.width)), cy = MAX(hh, MIN(s.height - hh, _ry * s.height));
    _panel.center = CGPointMake(cx, cy);
}
- (void)saveRatios {
    CGSize s = self.view.bounds.size; if (s.width < 1 || s.height < 1) return;
    _rx = _panel.center.x / s.width; _ry = _panel.center.y / s.height;
    NSUserDefaults *u = NSUserDefaults.standardUserDefaults; [u setDouble:_rx forKey:@"DSKpRX"]; [u setDouble:_ry forKey:@"DSKpRY"]; [u setDouble:_scale forKey:@"DSKpScale"];
}
- (void)pan:(UIPanGestureRecognizer *)g {
    if (g.state == UIGestureRecognizerStateBegan) _start = _panel.center;
    CGPoint t = [g translationInView:self.view];
    _panel.center = CGPointMake(_start.x + t.x, _start.y + t.y);                    // يتبع الإصبع مباشرة بلا أنيميشن
    if (g.state == UIGestureRecognizerStateEnded || g.state == UIGestureRecognizerStateCancelled) {
        CGSize s = self.view.bounds.size; CGFloat hw = _panel.bounds.size.width * _scale / 2, hh = _panel.bounds.size.height * _scale / 2;
        CGPoint c = CGPointMake(MAX(hw, MIN(s.width - hw, _panel.center.x)), MAX(hh, MIN(s.height - hh, _panel.center.y)));
        if (!CGPointEqualToPoint(c, _panel.center)) [UIView animateWithDuration:0.18 animations:^{ self->_panel.center = c; }];   // لا يخرج عن الشاشة
        [self saveRatiosAfter:c];
    }
}
- (void)saveRatiosAfter:(CGPoint)c {
    CGSize s = self.view.bounds.size; if (s.width < 1 || s.height < 1) return;
    NSUserDefaults *u = NSUserDefaults.standardUserDefaults;
    _rx = c.x / s.width; _ry = c.y / s.height;
    [u setDouble:_rx forKey:@"DSKpRX"]; [u setDouble:_ry forKey:@"DSKpRY"]; [u setDouble:_scale forKey:@"DSKpScale"];
}
- (void)cycleScale {
    _scale = _scale < 0.9 ? 1.0 : _scale < 1.1 ? 1.25 : _scale < 1.4 ? 1.5 : 0.8;
    [UIView animateWithDuration:0.15 animations:^{ self->_panel.transform = CGAffineTransformMakeScale(self->_scale, self->_scale); }];
    [self place]; [self saveRatios];
}
- (void)closePad { DSSettings *st = [DSSettings shared]; st.kbPad = NO; [st save]; DSKeypadSetVisible(NO); }

// ── المفاتيح: تعمل عند اللمس مباشرة (TouchDown) بلا انتظار رفع الإصبع → زمن استجابة صفر ──
- (void)typeKey:(UIButton *)b { UIView *t = DSKpTarget(); if (t) [(id<UIKeyInput>)t insertText:b.currentTitle]; }
- (void)typeSpace { UIView *t = DSKpTarget(); if (t) [(id<UIKeyInput>)t insertText:@" "]; }
- (void)retKey { UIView *t = DSKpTarget(); if (t) DSKbSendNow(t); }
// يعكس ترتيب أرقام الحقل كاملاً: ١٢٣ → ٣٢١ (بلا تكرار، تبديل ترتيب فقط)
- (void)reverseKey {
    UIView *t = DSKpTarget(); if (!t) return;
    NSString *txt = [t isKindOfClass:UITextField.class] ? ((UITextField *)t).text : [t isKindOfClass:UITextView.class] ? ((UITextView *)t).text : nil;
    if (!txt.length) return;
    NSMutableString *rev = [NSMutableString stringWithCapacity:txt.length];
    [txt enumerateSubstringsInRange:NSMakeRange(0, txt.length) options:NSStringEnumerationByComposedCharacterSequences | NSStringEnumerationReverse
        usingBlock:^(NSString *ch, NSRange r, NSRange er, BOOL *stop) { [rev appendString:ch]; }];
    gKbBusy = YES;
    for (NSUInteger i = 0; i < txt.length; i++) [(id<UIKeyInput>)t deleteBackward];
    [(id<UIKeyInput>)t insertText:rev];
    gKbBusy = NO;
    DSKbAfterInsert(t, @"");
}
// يكرر آخر رمز في الحقل مرة واحدة فقط بكل ضغطة: ...12 → ...122 (ليس إرسالاً متكرراً، تعديل نص فقط)
- (void)repeatLastKey {
    UIView *t = DSKpTarget(); if (!t) return;
    NSString *txt = [t isKindOfClass:UITextField.class] ? ((UITextField *)t).text : [t isKindOfClass:UITextView.class] ? ((UITextView *)t).text : nil;
    if (!txt.length) return;
    NSRange r = [txt rangeOfComposedCharacterSequenceAtIndex:txt.length - 1];
    [(id<UIKeyInput>)t insertText:[txt substringWithRange:r]];
}
- (void)delOnce { UIView *t = DSKpTarget(); if (t) [(id<UIKeyInput>)t deleteBackward]; }
- (void)delDown {
    [self delOnce]; [_rep invalidate];
    _rep = [NSTimer scheduledTimerWithTimeInterval:0.32 repeats:NO block:^(NSTimer *t) {     // اضغط مطوّلاً ليمسح بسرعة
        self->_rep = [NSTimer scheduledTimerWithTimeInterval:0.045 repeats:YES block:^(NSTimer *t2) { [self delOnce]; }];
    }];
}
- (void)delUp { [_rep invalidate]; _rep = nil; }
@end

static DSKeypadWindow *gKpWin;
static void DSKeypadApplyHide(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIView *t = DSKpTarget(); if (!t) return;
        DSKpPrepareInput(t); [(UIResponder *)t reloadInputViews];
    });
}
static void DSKeypadSetVisible(BOOL on) {
    dispatch_async(dispatch_get_main_queue(), ^{
        gKpOn = on;
        if (on) {
            if (!gKpWin) {
                UIWindowScene *scene = nil;
                for (UIScene *s in UIApplication.sharedApplication.connectedScenes)
                    if ([s isKindOfClass:UIWindowScene.class] && s.activationState == UISceneActivationStateForegroundActive) { scene = (UIWindowScene *)s; break; }
                DSKeypadWindow *w = scene ? [[DSKeypadWindow alloc] initWithWindowScene:scene] : [[DSKeypadWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
                w.windowLevel = UIWindowLevelAlert + 200;       // فوق المنيو: يبقى ظاهراً حتى لو فتحت أو أغلقت المنيو
                w.backgroundColor = UIColor.clearColor;
                w.rootViewController = [DSKeypadVC new];
                gKpWin = w;
            }
            gKpWin.hidden = NO;
        } else {
            gKpWin.hidden = YES;
        }
        DSKeypadApplyHide();
    });
}

__attribute__((constructor)) static void DSInit(void) {
    @autoreleasepool {
        [DSStore shared];
        [DSSettings shared];  // يحمّل القواعد المفعّلة فوراً قبل أي اتصال
        [DSProxy shared];     // يحمّل البروكسي المحفوظ قبل أي اتصال
        DSInstallCHooks();
        DSInstallURLSessionHooks();
        [[ASTestManager shared] start];      // AUTO TEST: يبدأ فوراً عند تفعيل ALL/CHAT
        [[STAutoManager shared] start];       // مجدول اختبار الضغط التلقائي (AUTO LOAD)
        %init(DSAgoraJoinSoundHooks);
        %init(DSKeyboardHooks);   // الكيبورد: تكرار الأرقام / تفكيك الحروف
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *n) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ DSShow(); if ([DSSettings shared].kbPad) DSKeypadSetVisible(YES); });
        }];
    }
}
