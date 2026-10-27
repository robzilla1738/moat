import Foundation
import NetworkExtension

// System extension entry point. The provider class is named in Info.plist (NEProviderClasses).
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
ExtensionRuntime.shared.startControlListener()
dispatchMain()
