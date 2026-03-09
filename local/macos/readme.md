### Notes on macos development

(double entendre intended)

Code signing on macos can be confusing, especially when working with cli tools.

When having difficulties with executing applications, first reach for the Mac Console app. (supplied with the OS)

Allows you to listen to events and get more detailed errors on the launch failures

investigate provisioning profiles with `security cms -D -i <profile_path>`

check your available codesigning identities with `security find-identity -v -p codesigning`

investigate log output (to apple unified logs): `log stream --predicate 'subsystem == "com.weatjar.notes"' --level debug`

#### Mistakes I made

- Not confirming that the email in the certificate signing request matches my apple id
- Provising using the Hardware UUID instead of the Provisioning UDID: 00008112-001C24A114E8A01E
- Not knowing Sign in with Apple is a *restricted* entitlement. https://developer.apple.com/help/account/reference/supported-capabilities-macos 
