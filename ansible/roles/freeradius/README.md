# WPA2-Enterprise Certificate Authentication

This repository contains the **Ansible automation used to manage client certificates for WPA2-Enterprise Wi-Fi authentication using EAP-TLS**.

Certificates are issued using **Step-CA** and authentication is handled by **FreeRADIUS**.

Two playbooks are provided:

- `wifi_cert.yml` → generate and export a client certificate  
- `wifi_revoke.yml` → revoke a certificate and block the device from Wi-Fi

---

# Generating a Wi-Fi Certificate

Run the playbook:

```bash
ansible-playbook wifi_cert.yml
```

You will be prompted for the client certificate name.

Example:

```
Client certificate name: alice_phone
```

The playbook will:

1. Generate a client certificate using Step-CA  
2. Export it as a **PKCS#12 bundle (.p12)**  
3. Download it to your machine  

Location:

```bash
~/Downloads/<cert_name>.p12
```

Example:

```bash
~/Downloads/alice_phone.p12
```

The `.p12` file contains:

- client certificate
- private key
- certificate chain

---

# Installing Certificate on Devices

## Android

1. Transfer the `.p12` certificate to the Android device  
   (AirDrop alternative, email, Google Drive, or USB).

2. Open **Settings**.

3. Navigate to:

```
Security → Encryption & Credentials → Install a Certificate → Wi-Fi Certificate
```

(On some devices: **Security → Install from storage**)

4. Select the `.p12` file.

5. Enter the **certificate password** if prompted.

6. The certificate will be installed into the **user credential store**.

---

### Connect to WPA2-Enterprise Wi-Fi

1. Open **Settings → Network & Internet → Wi-Fi**

2. Select the WPA2-Enterprise network.

3. Configure the authentication settings:

```
EAP Method: TLS
CA Certificate: Use system certificates (or select installed Root CA)
User Certificate: <client certificate>
Identity: leave empty
Anonymous Identity: leave empty
```

4. Tap **Connect**.

Android will now authenticate using the installed **client certificate via EAP-TLS**.

## macOS

1. Double-click the `.p12` file  
2. Import it into **Keychain Access**  
3. Install the **Root CA certificate** if not already installed  
4. Connect to Wi-Fi and configure:

```
Security: WPA2-Enterprise
EAP Method: TLS
Identity: Certificate
```

macOS will automatically select the installed certificate.

---

## Windows / Linux Laptop

1. Import the `.p12` certificate into the system certificate store  
2. Install the **Root CA certificate**  
3. Connect to Wi-Fi and configure:

```
Security: WPA2-Enterprise
Authentication: TLS
Certificate: client certificate
```

---

## iPhone / iPad

1. Transfer the `.p12` file to the device  
2. Open it and install the certificate profile  
3. Install the **Root CA certificate**  
4. Join the Wi-Fi network and configure:

```
EAP Method: TLS
Identity: Client Certificate
```

---

# Revoking a Wi-Fi Certificate

To revoke a device's Wi-Fi access, run:

```bash
ansible-playbook wifi_revoke.yml
```

Example prompt:

```
Client certificate name: alice_phone
```

The playbook will:

1. Extract the certificate **serial number**
2. Print the command required to revoke the certificate on the CA server

Example output:

```
Run the following command on auth.server.acme to revoke the certificate:
step ca revoke <cert_serial>
```

Run the printed command on the auth.server.acme:

```bash
step ca revoke <cert_serial>
```

After this, the device **will no longer be able to authenticate to Wi-Fi**.

# Checking Revoked Certificates

Revoked certificate serial numbers are stored in:

```bash
/etc/freeradius/3.0/mods-config/files/authorize
```

Example entries:

```
CD75A4298B37BA1F2B10B20C7BE1F164 Auth-Type := Reject
25219F8644209B84A1E3E92F6CD5E4EB Auth-Type := Reject
```

You can view them with:

```bash
cat /etc/freeradius/3.0/mods-config/files/authorize
```

---


# Summary

Workflow:

```
wifi_cert.yml
↓
Generate certificate
↓
Install on device
↓
Connect to WPA2-Enterprise Wi-Fi
```

If a device must be blocked:

```
wifi_revoke.yml
↓
Revoke certificate
↓
Serial added to revoke list
↓
FreeRADIUS blocks the device
```
