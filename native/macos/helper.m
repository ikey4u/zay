// Zay's native authorization and narrowly scoped XPC launcher. The installed
// executable is also the networking worker; clients cannot supply a program.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <ServiceManagement/ServiceManagement.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <signal.h>

static NSString *const Service = @"dev.zay.desktop.helper";

@protocol ZayHelperProtocol
- (void)versionWithReply:(void (^)(NSString *))reply;
- (void)startCoreAt:(NSString *)directory config:(NSString *)config reply:(void (^)(int, NSString *))reply;
@end

static NSDictionary *Info(void) {
    return (__bridge NSDictionary *)CFBundleGetInfoDictionary(CFBundleGetMainBundle());
}
static void ErrorText(char *buffer, size_t length, NSString *message) {
    if (length) snprintf(buffer, length, "%s", message.UTF8String ?: "macOS helper error");
}

// Code-signing requirements are checked by XPC for every message (macOS 13+),
// rather than checking a caller-supplied PID or executable path.
static NSXPCConnection *Connect(NSString *requirement) {
    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:Service options:NSXPCConnectionPrivileged];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ZayHelperProtocol)];
    [connection setCodeSigningRequirement:requirement];
    [connection activate];
    return connection;
}
static BOOL CurrentHelper(NSXPCConnection *connection, NSString *expectedBuild, NSString **failure) {
    __block NSString *detail = nil;
    __block BOOL current = NO;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    id<ZayHelperProtocol> proxy = [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        detail = [NSString stringWithFormat:@"%@ (%@ %ld)", error.localizedDescription, error.domain, (long)error.code];
        dispatch_semaphore_signal(done);
    }];
    [proxy versionWithReply:^(NSString *version) {
        current = [version isEqual:expectedBuild];
        if (!current) detail = @"The installed helper belongs to a different Zay build.";
        dispatch_semaphore_signal(done);
    }];
    // A cold helper start includes Gatekeeper and signature checks. These took
    // over five seconds on macOS; do not cancel a successful first installation.
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC)) != 0) {
        if (failure) *failure = @"The helper did not respond within 30 seconds. Check whether Zay is allowed in System Settings > General > Login Items & Extensions.";
        return NO;
    }
    if (failure) *failure = detail;
    return current;
}
static BOOL Install(char *error, size_t length) {
    AuthorizationRef authorization = NULL;
    AuthorizationItem item = {kSMRightBlessPrivilegedHelper, 0, NULL, 0};
    AuthorizationRights rights = {1, &item};
    AuthorizationFlags flags = kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize;
    const char *purpose = "Zay needs to install its networking helper so TUN and Mesh node mode can create virtual network interfaces and manage network routes. The Zay app continues running under your account.";
    AuthorizationItem explanation = {kAuthorizationEnvironmentPrompt, strlen(purpose), (void *)purpose, 0};
    AuthorizationEnvironment environment = {1, &explanation};
    OSStatus status = AuthorizationCreate(&rights, &environment, flags, &authorization);
    if (status != errAuthorizationSuccess) {
        ErrorText(error, length, status == errAuthorizationCanceled ? @"Administrator authorization was cancelled." : [NSString stringWithFormat:@"macOS authorization failed (%d).", status]);
        return NO;
    }
    CFErrorRef failure = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    BOOL installed = SMJobBless(kSMDomainSystemLaunchd, (__bridge CFStringRef)Service, authorization, &failure);
#pragma clang diagnostic pop
    AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    if (!installed) ErrorText(error, length, failure ? ((__bridge NSError *)failure).localizedDescription : @"Could not install Zay's networking helper.");
    if (failure) CFRelease(failure);
    return installed;
}

// Called on a blocking background thread, only when settings require root.
// Returned retained connection owns the worker session until release.
void *zay_macos_start(const char *directory, const char *config, int *pid, char *error, size_t length) {
    @autoreleasepool {
        NSDictionary *info = Info();
        NSString *requirement = info[@"SMPrivilegedExecutables"][Service];
        if (![info[@"ZayPrivilegedHelperSigningReady"] boolValue] || !requirement.length) {
            ErrorText(error, length, @"TUN and Mesh node mode require the signed Zay Desktop app bundle. Build it with APPLE_SIGN_IDENTITY set to your Apple Development or Developer ID Application identity.");
            return NULL;
        }
        NSXPCConnection *connection = Connect(requirement);
        NSString *helperFailure = nil;
        if (!CurrentHelper(connection, info[@"ZayHelperBuild"], &helperFailure)) {
            [connection invalidate];
            if (!Install(error, length)) return NULL;
            connection = Connect(requirement);
            if (!CurrentHelper(connection, info[@"ZayHelperBuild"], &helperFailure)) {
                [connection invalidate];
                ErrorText(error, length, [NSString stringWithFormat:@"The installed Zay networking helper is unavailable: %@", helperFailure ?: @"No reply was received."]);
                return NULL;
            }
        }
        __block int worker = 0;
        __block NSString *failure = nil;
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        id<ZayHelperProtocol> proxy = [connection remoteObjectProxyWithErrorHandler:^(NSError *e) { failure = e.localizedDescription; dispatch_semaphore_signal(done); }];
        [proxy startCoreAt:@(directory) config:@(config) reply:^(int process, NSString *message) { worker = process; failure = message; dispatch_semaphore_signal(done); }];
        if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC)) != 0) {
            [connection invalidate];
            ErrorText(error, length, @"Timed out waiting for Zay's networking helper.");
            return NULL;
        }
        if (worker <= 0) {
            [connection invalidate];
            ErrorText(error, length, failure ?: @"The Zay networking worker could not start.");
            return NULL;
        }
        *pid = worker;
        return (__bridge_retained void *)connection;
    }
}
void zay_macos_release(void *handle) {
    @autoreleasepool {
        NSXPCConnection *connection = (__bridge_transfer NSXPCConnection *)handle;
        [connection invalidate];
    }
}

static BOOL ValidPaths(NSString *directory, NSString *config, uid_t uid) {
    // Require actual, caller-owned files. Reject symlink aliases and a
    // configuration outside the caller's private data directory.
    char resolvedDirectory[PATH_MAX], resolvedConfig[PATH_MAX];
    struct stat folder, file;
    return realpath(directory.fileSystemRepresentation, resolvedDirectory)
            && realpath(config.fileSystemRepresentation, resolvedConfig)
            && strcmp(directory.fileSystemRepresentation, resolvedDirectory) == 0
            && strcmp(config.fileSystemRepresentation, resolvedConfig) == 0
            && directory.isAbsolutePath && config.isAbsolutePath
            && [config.stringByDeletingLastPathComponent isEqual:directory]
            && [config.lastPathComponent isEqual:@"zay.toml"]
            && lstat(directory.fileSystemRepresentation, &folder) == 0 && S_ISDIR(folder.st_mode) && folder.st_uid == uid && (folder.st_mode & 0022) == 0
            && lstat(config.fileSystemRepresentation, &file) == 0 && S_ISREG(file.st_mode) && file.st_uid == uid && (file.st_mode & 0077) == 0;
}
int zay_macos_validate_paths(const char *directory, const char *config, unsigned int uid) {
    @autoreleasepool { return ValidPaths(@(directory), @(config), uid); }
}

@interface ZaySession : NSObject <ZayHelperProtocol>
@property(nonatomic, strong) NSTask *worker;
@property(nonatomic) pid_t parent;
@property(nonatomic) uid_t uid;
@property(nonatomic) gid_t gid;
- (void)stop;
@end
@implementation ZaySession
- (void)versionWithReply:(void (^)(NSString *))reply { reply(Info()[@"ZayHelperBuild"]); }
- (void)startCoreAt:(NSString *)directory config:(NSString *)config reply:(void (^)(int, NSString *))reply {
    @synchronized(self) {
        if (self.worker.running) { reply(0, @"This connection already owns a networking worker."); return; }
        BOOL valid = ValidPaths(directory, config, self.uid);
        if (!valid) { reply(0, @"The networking configuration must belong to the current user in their Zay data directory."); return; }
        char executable[PATH_MAX]; uint32_t size = sizeof(executable);
        if (_NSGetExecutablePath(executable, &size) != 0) { reply(0, @"Could not locate the installed networking helper."); return; }
        NSTask *task = [NSTask new];
        task.executableURL = [NSURL fileURLWithPath:@(executable)];
        task.arguments = @[@"--run-core", @"--core-parent-pid", [NSString stringWithFormat:@"%d", self.parent], @"--data-dir", directory, @"--config", config];
        task.environment = @{@"PATH": @"/usr/bin:/bin:/usr/sbin:/sbin", @"SUDO_UID": [NSString stringWithFormat:@"%u", self.uid], @"SUDO_GID": [NSString stringWithFormat:@"%u", self.gid]};
        task.standardInput = [NSFileHandle fileHandleWithNullDevice];
        task.standardOutput = [NSFileHandle fileHandleWithNullDevice];
        task.standardError = [NSFileHandle fileHandleWithNullDevice];
        NSError *failure = nil;
        if (![task launchAndReturnError:&failure]) { reply(0, failure.localizedDescription); return; }
        self.worker = task;
        reply(task.processIdentifier, nil);
    }
}
- (void)stop {
    @synchronized(self) {
        NSTask *task = self.worker;
        if (task.running) {
            [task terminate]; // Core handles SIGTERM and restores its routes.
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                if (task.running) kill(task.processIdentifier, SIGKILL);
            });
        }
    }
}
@end

@interface ZayListener : NSObject <NSXPCListenerDelegate>
@property(nonatomic, strong) NSMutableSet<NSXPCConnection *> *connections;
@end
@implementation ZayListener
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    NSString *requirement = [Info()[@"SMAuthorizedClients"] firstObject];
    if (!requirement.length || connection.effectiveUserIdentifier == 0) return NO;
    [connection setCodeSigningRequirement:requirement];
    ZaySession *session = [ZaySession new];
    session.parent = connection.processIdentifier;
    session.uid = connection.effectiveUserIdentifier;
    session.gid = connection.effectiveGroupIdentifier;
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ZayHelperProtocol)];
    connection.exportedObject = session;
    @synchronized(self) {
        if (!self.connections) self.connections = [NSMutableSet new];
        [self.connections addObject:connection];
    }
    __weak ZayListener *owner = self;
    __weak NSXPCConnection *weakConnection = connection;
    connection.invalidationHandler = ^{
        [session stop];
        ZayListener *strongOwner = owner;
        @synchronized(strongOwner) { [strongOwner.connections removeObject:weakConnection]; }
    };
    [connection activate];
    return YES;
}
@end
int zay_macos_helper_run(void) {
    @autoreleasepool {
        if (geteuid() != 0) return 1;
        ZayListener *delegate = [ZayListener new];
        NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:Service];
        listener.delegate = delegate;
        [listener activate];
        [[NSRunLoop currentRunLoop] run];
        return 0;
    }
}

// Inert probe fixture for regression tests: no Mach service, authorization,
// worker, or networking is touched. Exercises cold replies and error handling.
@interface ZayProbeFixture : NSObject
@property(nonatomic) double delay;
@property(nonatomic) BOOL fail;
@property(nonatomic, copy) void (^errorHandler)(NSError *);
@end
@implementation ZayProbeFixture
- (id)remoteObjectProxyWithErrorHandler:(void (^)(NSError *))handler {
    self.errorHandler = handler;
    return self;
}
- (void)versionWithReply:(void (^)(NSString *))reply {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, self.delay * NSEC_PER_SEC), dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        if (self.fail) self.errorHandler([NSError errorWithDomain:@"ZayProbeFixture" code:4099 userInfo:@{NSLocalizedDescriptionKey: @"fixture connection refused"}]);
        else reply(@"fixture-build");
    });
}
@end
int zay_macos_probe_fixture(double delay, int fail, char *error, size_t length) {
    @autoreleasepool {
        ZayProbeFixture *fixture = [ZayProbeFixture new];
        fixture.delay = delay;
        fixture.fail = fail;
        NSString *detail = nil;
        BOOL current = CurrentHelper((NSXPCConnection *)fixture, @"fixture-build", &detail);
        if (!current) ErrorText(error, length, detail);
        return current;
    }
}
