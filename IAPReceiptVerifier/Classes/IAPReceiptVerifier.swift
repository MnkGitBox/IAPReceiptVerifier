//
//  Copyright 2016 Lionheart Software LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
import UIKit

public typealias Receipt = [String: Any]

public extension SecKey {
    static func generateBase64Encoded2048BitRSAKey() throws -> (private: String, public: String) {
        let type = kSecAttrKeyTypeRSA
        let attributes: [String: Any] =
            [kSecAttrKeyType as String: type,
             kSecAttrKeySizeInBits as String: 2048
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let data = SecKeyCopyExternalRepresentation(key, &error) as Data?,
            let publicKey = SecKeyCopyPublicKey(key),
            let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
                throw error!.takeRetainedValue() as Error
        }

        return (private: data.base64EncodedString(), public: publicKeyData.base64EncodedString())
    }
}

public struct IAPReceiptVerifier {
    var key: SecKey?
    var url: URL

    public init(url: URL) {
        self.url = url
    }

    public init?(url: URL, base64EncodedPublicKey string: String) {
        guard let keyData = Data(base64Encoded: string) else {
            return nil
        }

        let options: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 2048
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, options as CFDictionary, &error) else {
            return nil
        }

        self.key = key
        self.url = url
    }

    public func verify(completion: @escaping (Receipt?, VerifyError) -> ()) {
        guard let receiptURL = Bundle.main.appStoreReceiptURL,
              let receiptData = try? Data(contentsOf: receiptURL) else {
            completion(nil, .noReceipet)
            return
        }
        
        guard Reacherbility.isInternetAccessible else{
            completion(nil,.noInternet)
            return
        }
        
        let encodedData = receiptData.base64EncodedData(options: [])
        var request = URLRequest(url: url)
        request.httpBody = encodedData
        request.httpMethod = "POST"
        
        let algorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        
        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            var error: Unmanaged<CFError>?
            
            guard let data = data,
                  let HTTPResponse = response as? HTTPURLResponse,
                  let object = try? JSONSerialization.jsonObject(with: data, options: []),
                  let json = object as? [String: Any] else {
                completion(nil, .jsonSerialization)
                return
            }
            
            if let key = self.key {
                guard let signatureString = HTTPResponse.allHeaderFields["X-Signature"] as? String,
                      let signature = Data(base64Encoded: signatureString),
                      SecKeyVerifySignature(key, algorithm, data as CFData, signature as CFData, &error) else {
                    completion(nil, .secKeyVerify)
                    return
                }
            }
            
            completion(json, .none)
        }
        task.resume()
    }
}


public enum VerifyError: String {
  case noReceipet
  case noInternet
  case jsonSerialization
  case secKeyVerify
  case undefine
  case none
}


import SystemConfiguration
struct Reacherbility{
    
    static var isInternetAccessible:Bool{
        
        var zeroAddress = sockaddr_in(sin_len: 0, sin_family: 0, sin_port: 0, sin_addr: in_addr(s_addr: 0), sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))
        zeroAddress.sin_len = UInt8(MemoryLayout.size(ofValue: zeroAddress))
        zeroAddress.sin_family = sa_family_t(AF_INET)
        
        let defaultRouteReachability = withUnsafePointer(to: &zeroAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {zeroSockAddress in
                SCNetworkReachabilityCreateWithAddress(nil, zeroSockAddress)
            }
        }
        
        var flags: SCNetworkReachabilityFlags = SCNetworkReachabilityFlags(rawValue: 0)
        if SCNetworkReachabilityGetFlags(defaultRouteReachability!, &flags) == false {
            return false
        }
        
        let isReachable = (flags.rawValue & UInt32(kSCNetworkFlagsReachable)) != 0
        let needsConnection = (flags.rawValue & UInt32(kSCNetworkFlagsConnectionRequired)) != 0
        let result = (isReachable && !needsConnection)
        
        return result
    }
}

