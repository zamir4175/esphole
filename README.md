# 🛡️ esphole - Block network ads with your hardware

[![Download Release](https://img.shields.io/badge/Download-Release-blue.svg)](https://github.com/zamir4175/esphole/releases)

## 🎯 About This Software

esphole acts as a filter for your home internet connection. It sits between your devices and the websites you visit. When a device requests a webpage, esphole checks if the site contains trackers or ads. If it finds them, it blocks the connection before it reaches your device. This speeds up your browsing and protects your privacy. You build this system on an ESP32-S3 microchip.

## 🛠️ System Requirements

You need the following items to use this software:

*   One ESP32-S3 development board.
*   A USB cable compatible with your board.
*   A Windows 10 or 11 computer.
*   A stable home Wi-Fi connection.

## 📥 Getting the Files

You must download the firmware files to your computer. These files contain the instructions that tell the ESP32 chip how to block network traffic.

[Visit the release page to download the latest software](https://github.com/zamir4175/esphole/releases)

Look for the file ending in `.bin`. Save this file to a folder where you can find it later, such as your Downloads folder.

## ⚙️ Setting Up Your Device

Follow these steps to put the software onto your ESP32-S3 board.

1. Connect the ESP32-S3 board to your computer using the USB cable.
2. Visit the website [web.esphome.io](https://web.esphome.io) in your Chrome or Edge browser.
3. Click the Connect button on the website.
4. Select the port that corresponds to your ESP32 board from the pop-up list.
5. Click the Install button on the website.
6. Choose the .bin file you downloaded earlier.
7. Wait while the browser writes the software to your hardware. The process bar completes in a few minutes.
8. Unplug your device once the progress bar shows 100 percent.

## 🌐 Configuring the Network

Once the software resides on your hardware, you must tell it how to connect to your home network.

1. Plug the ESP32-S3 back into a power source, such as a USB wall charger.
2. Wait one minute for the device to start.
3. Open the Wi-Fi settings on your phone or computer.
4. Look for a network named "esphole-setup" and connect to it.
5. A page should open automatically. Choose your home Wi-Fi network from the list.
6. Enter your home Wi-Fi password.
7. Save your settings. The device will restart and connect to your home Wi-Fi.

## 📊 Using the Web Interface

esphole provides a web page to manage your blockers. You can switch between light and dark modes to suit your preference.

1. Locate the IP address of your device through your router’s admin panel or search for "esphole.local" in your browser.
2. Use the dashboard to view blocked requests in real-time.
3. You can add specific websites to a whitelist if a site does not load correctly.
4. The system uses encrypted connections for all requests to ensure your internet provider cannot track what you visit.

## 🔄 Updating and Maintenance

The software features an automated rollback system. If an update fails, the device automatically returns to the last working version. This prevents the hardware from becoming unresponsive. To update your firmware, simply visit the release page again, download the new file, and repeat the setup process.

## 🛡️ Privacy Features

- **Ad and Tracker Blocking:** Prevents hundreds of known tracking scripts from loading.
- **Encrypted Upstream:** Sends your DNS requests through secure channels to prevent snooping.
- **Fail-Open Design:** If the hardware loses power, your internet will continue to work normally, rather than stopping your connection.
- **Local Control:** All your filtering logs stay on the device. Data never leaves your home network.

## ❓ Troubleshooting

If the device does not appear to block ads, ensure that your computer and the ESP32-S3 are on the same Wi-Fi network. If you cannot access the web interface, try unplugging the device for ten seconds and plugging it back in to restart the service. Resetting the device is safe and will not clear your configuration settings.

Keywords: ad-blocker, adblock, c, dns, dns-over-tls, dns-server, dns-sinkhole, esp-idf, esp32, esp32-s3, firmware, freertos, iot, network-security, pi-hole