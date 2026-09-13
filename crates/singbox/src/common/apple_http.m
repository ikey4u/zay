#import "apple_http.h"

#import <CoreFoundation/CFStream.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dispatch/dispatch.h>
#import <objc/runtime.h>
#import <stdlib.h>
#import <string.h>

struct singbox_apple_http_session {
    void *handle;
};

struct singbox_apple_http_task {
    void *task;
    void *done_semaphore;
    singbox_apple_http_response_t *response;
    char *error;
};

static NSString *const singbox_apple_http_verify_time_key = @"singbox.verify-time";
static char singbox_apple_http_verify_time_association_key;

static void singbox_set_error(char **error_out, NSString *message) {
    if (error_out == NULL || *error_out != NULL) {
        return;
    }
    const char *value = message.UTF8String;
    *error_out = strdup(value != NULL ? value : "unknown error");
}

static void singbox_set_nserror(char **error_out, NSError *error) {
    singbox_set_error(error_out, error.localizedDescription ?: error.description ?: @"unknown error");
}

static bool singbox_evaluate_trust(
    SecTrustRef trust,
    NSArray *anchors,
    bool anchor_only,
    NSDate *verify_date
) {
    if (trust == NULL) {
        return false;
    }
    if (verify_date != nil && SecTrustSetVerifyDate(trust, (__bridge CFDateRef)verify_date) != errSecSuccess) {
        return false;
    }
    if (anchors.count > 0 || anchor_only) {
        SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)anchors);
        SecTrustSetAnchorCertificatesOnly(trust, anchor_only);
    }
    CFErrorRef error = NULL;
    bool result = SecTrustEvaluateWithError(trust, &error);
    if (error != NULL) {
        CFRelease(error);
    }
    return result;
}

static NSDate *singbox_verify_date_for_task(NSURLSessionTask *task) {
    id associated = objc_getAssociatedObject(task, &singbox_apple_http_verify_time_association_key);
    if ([associated isKindOfClass:[NSNumber class]]) {
        return [NSDate dateWithTimeIntervalSince1970:[(NSNumber *)associated longLongValue] / 1000.0];
    }
    NSURLRequest *request = task.currentRequest ?: task.originalRequest;
    if (request == nil) {
        return nil;
    }
    id value = [NSURLProtocol propertyForKey:singbox_apple_http_verify_time_key inRequest:request];
    if (![value isKindOfClass:[NSNumber class]]) {
        return nil;
    }
    return [NSDate dateWithTimeIntervalSince1970:[(NSNumber *)value longLongValue] / 1000.0];
}

static singbox_apple_http_response_t *singbox_create_response(
    NSHTTPURLResponse *http_response,
    NSData *data
) {
    singbox_apple_http_response_t *response = calloc(1, sizeof(*response));
    response->status_code = (int)http_response.statusCode;
    NSDictionary *headers = http_response.allHeaderFields;
    response->header_count = headers.count;
    if (response->header_count > 0) {
        response->header_keys = calloc(response->header_count, sizeof(char *));
        response->header_values = calloc(response->header_count, sizeof(char *));
        NSUInteger index = 0;
        for (id key in headers) {
            NSString *key_string = [key description];
            NSString *value_string = [headers[key] description];
            response->header_keys[index] = strdup(key_string.UTF8String ?: "");
            response->header_values[index] = strdup(value_string.UTF8String ?: "");
            index++;
        }
    }
    if (data.length > 0) {
        response->body_len = data.length;
        response->body = malloc(data.length);
        memcpy(response->body, data.bytes, data.length);
    }
    return response;
}

@interface SingboxAppleHTTPSessionDelegate : NSObject <NSURLSessionTaskDelegate>
@property(nonatomic, assign) BOOL insecure;
@property(nonatomic, assign) BOOL anchorOnly;
@property(nonatomic, strong) NSArray *anchors;
@property(nonatomic, strong) NSData *pinnedPublicKeyHashes;
@end

@implementation SingboxAppleHTTPSessionDelegate

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler {
    completionHandler(nil);
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }
    SecTrustRef trust = challenge.protectionSpace.serverTrust;
    if (trust == NULL) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }
    NSDate *verify_date = singbox_verify_date_for_task(task);
    BOOL custom = self.insecure || self.anchorOnly || self.anchors.count > 0 || self.pinnedPublicKeyHashes.length > 0 || verify_date != nil;
    if (!custom) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }
    BOOL ok = self.insecure || singbox_evaluate_trust(trust, self.anchors, self.anchorOnly, verify_date);
    if (ok && self.pinnedPublicKeyHashes.length > 0) {
        CFArrayRef chain = SecTrustCopyCertificateChain(trust);
        SecCertificateRef leaf = NULL;
        if (chain != NULL && CFArrayGetCount(chain) > 0) {
            leaf = (SecCertificateRef)CFArrayGetValueAtIndex(chain, 0);
        }
        if (leaf == NULL) {
            ok = NO;
        } else {
            NSData *leaf_data = CFBridgingRelease(SecCertificateCopyData(leaf));
            char *pin_error = singbox_apple_http_verify_public_key_sha256(
                self.pinnedPublicKeyHashes.bytes,
                self.pinnedPublicKeyHashes.length,
                leaf_data.bytes,
                leaf_data.length
            );
            if (pin_error != NULL) {
                free(pin_error);
                ok = NO;
            }
        }
        if (chain != NULL) {
            CFRelease(chain);
        }
    }
    if (!ok) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }
    completionHandler(
        NSURLSessionAuthChallengeUseCredential,
        [NSURLCredential credentialForTrust:trust]
    );
}

@end

@interface SingboxAppleHTTPSessionHandle : NSObject
@property(nonatomic, strong) NSURLSession *session;
@property(nonatomic, strong) SingboxAppleHTTPSessionDelegate *delegate;
@end

@implementation SingboxAppleHTTPSessionHandle
@end

singbox_apple_http_session_t *singbox_apple_http_session_create(
    const singbox_apple_http_session_config_t *config,
    char **error_out
) {
    @autoreleasepool {
        NSURLSessionConfiguration *session_config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        session_config.URLCache = nil;
        session_config.HTTPCookieStorage = nil;
        session_config.URLCredentialStorage = nil;
        session_config.HTTPShouldSetCookies = NO;
        if (config != NULL && config->proxy_host != NULL && config->proxy_port > 0) {
            NSMutableDictionary *proxy = [NSMutableDictionary dictionary];
            proxy[(__bridge NSString *)kCFStreamPropertySOCKSProxyHost] = [NSString stringWithUTF8String:config->proxy_host];
            proxy[(__bridge NSString *)kCFStreamPropertySOCKSProxyPort] = @(config->proxy_port);
            proxy[(__bridge NSString *)kCFStreamPropertySOCKSVersion] = (__bridge NSString *)kCFStreamSocketSOCKSVersion5;
            if (config->proxy_username != NULL) {
                proxy[(__bridge NSString *)kCFStreamPropertySOCKSUser] = [NSString stringWithUTF8String:config->proxy_username];
            }
            if (config->proxy_password != NULL) {
                proxy[(__bridge NSString *)kCFStreamPropertySOCKSPassword] = [NSString stringWithUTF8String:config->proxy_password];
            }
            session_config.connectionProxyDictionary = proxy;
        }
        if (config != NULL && config->min_tls_version != 0) {
            session_config.TLSMinimumSupportedProtocolVersion = (tls_protocol_version_t)config->min_tls_version;
        }
        if (config != NULL && config->max_tls_version != 0) {
            session_config.TLSMaximumSupportedProtocolVersion = (tls_protocol_version_t)config->max_tls_version;
        }
        SingboxAppleHTTPSessionDelegate *delegate = [[SingboxAppleHTTPSessionDelegate alloc] init];
        delegate.anchors = @[];
        if (config != NULL) {
            delegate.insecure = config->insecure;
            delegate.anchorOnly = config->anchor_only;
            if (config->anchor_certificate_count > 0) {
                NSMutableArray *anchors = [NSMutableArray arrayWithCapacity:config->anchor_certificate_count];
                for (size_t index = 0; index < config->anchor_certificate_count; index++) {
                    NSData *data = [NSData dataWithBytes:config->anchor_certificates[index]
                                                  length:config->anchor_certificate_lengths[index]];
                    SecCertificateRef certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
                    if (certificate == NULL) {
                        singbox_set_error(error_out, @"parse Apple trust anchor");
                        return NULL;
                    }
                    [anchors addObject:(__bridge id)certificate];
                    CFRelease(certificate);
                }
                delegate.anchors = anchors;
            }
            if (config->pinned_public_key_sha256_len > 0) {
                delegate.pinnedPublicKeyHashes = [NSData dataWithBytes:config->pinned_public_key_sha256
                                                                 length:config->pinned_public_key_sha256_len];
            }
        }
        NSURLSession *session = [NSURLSession sessionWithConfiguration:session_config
                                                              delegate:delegate
                                                         delegateQueue:nil];
        if (session == nil) {
            singbox_set_error(error_out, @"create Apple HTTP session");
            return NULL;
        }
        SingboxAppleHTTPSessionHandle *handle = [[SingboxAppleHTTPSessionHandle alloc] init];
        handle.session = session;
        handle.delegate = delegate;
        singbox_apple_http_session_t *session_handle = calloc(1, sizeof(*session_handle));
        session_handle->handle = (__bridge_retained void *)handle;
        return session_handle;
    }
}

void singbox_apple_http_session_close(singbox_apple_http_session_t *session) {
    if (session == NULL || session->handle == NULL) {
        return;
    }
    SingboxAppleHTTPSessionHandle *handle = (__bridge_transfer SingboxAppleHTTPSessionHandle *)session->handle;
    [handle.session invalidateAndCancel];
    free(session);
}

singbox_apple_http_task_t *singbox_apple_http_session_send_async(
    singbox_apple_http_session_t *session,
    const singbox_apple_http_request_t *request,
    char **error_out
) {
    @autoreleasepool {
        if (session == NULL || session->handle == NULL || request == NULL || request->method == NULL || request->url == NULL) {
            singbox_set_error(error_out, @"invalid Apple HTTP request");
            return NULL;
        }
        SingboxAppleHTTPSessionHandle *handle = (__bridge SingboxAppleHTTPSessionHandle *)session->handle;
        NSURL *url = [NSURL URLWithString:[NSString stringWithUTF8String:request->url]];
        if (url == nil) {
            singbox_set_error(error_out, @"invalid Apple HTTP URL");
            return NULL;
        }
        NSMutableURLRequest *url_request = [NSMutableURLRequest requestWithURL:url];
        url_request.HTTPMethod = [NSString stringWithUTF8String:request->method];
        for (size_t index = 0; index < request->header_count; index++) {
            if (request->header_keys[index] != NULL && request->header_values[index] != NULL) {
                [url_request addValue:[NSString stringWithUTF8String:request->header_values[index]]
                   forHTTPHeaderField:[NSString stringWithUTF8String:request->header_keys[index]]];
            }
        }
        if (request->body_len > 0) {
            url_request.HTTPBody = [NSData dataWithBytes:request->body length:request->body_len];
        }
        if (request->has_verify_time) {
            [NSURLProtocol setProperty:@(request->verify_time_unix_millis)
                                forKey:singbox_apple_http_verify_time_key
                             inRequest:url_request];
        }
        singbox_apple_http_task_t *task = calloc(1, sizeof(*task));
        dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
        task->done_semaphore = (__bridge_retained void *)semaphore;
        NSURLSessionDataTask *data_task = [handle.session dataTaskWithRequest:url_request
                                                           completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error != nil) {
                singbox_set_nserror(&task->error, error);
            } else if (![response isKindOfClass:[NSHTTPURLResponse class]]) {
                singbox_set_error(&task->error, @"unexpected Apple HTTP response type");
            } else {
                task->response = singbox_create_response((NSHTTPURLResponse *)response, data ?: [NSData data]);
            }
            dispatch_semaphore_signal((__bridge dispatch_semaphore_t)task->done_semaphore);
        }];
        if (data_task == nil) {
            singbox_set_error(error_out, @"create Apple HTTP data task");
            singbox_apple_http_task_close(task);
            return NULL;
        }
        if (request->has_verify_time) {
            objc_setAssociatedObject(
                data_task,
                &singbox_apple_http_verify_time_association_key,
                @(request->verify_time_unix_millis),
                OBJC_ASSOCIATION_RETAIN_NONATOMIC
            );
        }
        task->task = (__bridge_retained void *)data_task;
        [data_task resume];
        return task;
    }
}

singbox_apple_http_response_t *singbox_apple_http_task_wait(
    singbox_apple_http_task_t *task,
    char **error_out
) {
    if (task == NULL || task->done_semaphore == NULL) {
        singbox_set_error(error_out, @"invalid Apple HTTP task");
        return NULL;
    }
    dispatch_semaphore_wait((__bridge dispatch_semaphore_t)task->done_semaphore, DISPATCH_TIME_FOREVER);
    if (task->error != NULL) {
        singbox_set_error(error_out, [NSString stringWithUTF8String:task->error]);
        return NULL;
    }
    return task->response;
}

void singbox_apple_http_task_cancel(singbox_apple_http_task_t *task) {
    if (task != NULL && task->task != NULL) {
        [(__bridge NSURLSessionTask *)task->task cancel];
    }
}

void singbox_apple_http_task_close(singbox_apple_http_task_t *task) {
    if (task == NULL) {
        return;
    }
    if (task->task != NULL) {
        __unused NSURLSessionTask *data_task = (__bridge_transfer NSURLSessionTask *)task->task;
    }
    if (task->done_semaphore != NULL) {
        __unused dispatch_semaphore_t semaphore = (__bridge_transfer dispatch_semaphore_t)task->done_semaphore;
    }
    free(task->error);
    free(task);
}

void singbox_apple_http_response_free(singbox_apple_http_response_t *response) {
    if (response == NULL) {
        return;
    }
    for (size_t index = 0; index < response->header_count; index++) {
        free(response->header_keys[index]);
        free(response->header_values[index]);
    }
    free(response->header_keys);
    free(response->header_values);
    free(response->body);
    free(response);
}
