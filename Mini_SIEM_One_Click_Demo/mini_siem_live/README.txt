MINI SIEM - WINDOWS SECURITY EVENT MONITOR
==========================================

ONE-CLICK LOCAL DEMO
1. Extract the entire ZIP folder.
2. Double-click START_SIEM.bat.
3. Approve the Windows Administrator prompt. This is needed to read the Windows Security log.
4. The script checks Python packages, starts the server, and opens the dashboard.
5. Local dashboard: http://127.0.0.1:5000
6. Default LOCAL demo login: admin / admin123
7. Keep the black command window open while monitoring.

SHARING WITH CLASSMATES
- Share the complete extracted project folder or ZIP, not just app.py.
- The other computer needs Windows 10/11 and Python 3.10+ installed and available as the 'python' command.
- Double-click START_SIEM.bat. It installs the listed Python packages automatically and asks for Administrator permission.
- Each computer monitors its OWN Windows Security log. It does not monitor your laptop remotely just because someone opens a copy of the folder.

OPTIONAL TEMPORARY ONLINE LINK
1. Install Cloudflare Tunnel once: winget install --id Cloudflare.cloudflared
2. Double-click start_online.bat and choose a new username/password.
3. Copy the https://...trycloudflare.com URL printed in the window.
4. Keep both windows open and keep the laptop awake and connected to the internet.
5. This temporary public URL changes when restarted. Anyone with the URL can reach the login page. Share it only with trusted people and use a strong password.
6. Do not use this demo tunnel for sensitive data or production hosting.

WHAT IT DOES
- Reads Windows Security logon events 4624 (successful) and 4625 (failed).
- Stores collected records in a local SQLite database.
- Detects 5 or more failed logons from the same known remote IP within 5 minutes.
- Refreshes the dashboard every 5 seconds.
- Does not create fake sample attacks, detect port scans, or block IP addresses.

IMPORTANT NOTES
- Windows auditing must record Logon events. Some events may show Unknown IP because local logons do not always include a remote address.
- A brute-force alert requires five failed logons from the same known non-local IP within five minutes. Ordinary local lock/unlock actions may not trigger it.
- This is a classroom demonstration, not a production-grade SIEM. The built-in demo login is only for local demonstration; use a new password for online sharing.

TROUBLESHOOTING
- If Python is not found, install Python 3.10+ and enable 'Add Python to PATH'.
- If packages fail to install, check internet access and run START_SIEM.bat again.
- If event collection reports error 1314, close the app and relaunch START_SIEM.bat, approving the Administrator prompt.
- If there are no events, confirm Windows Security auditing is enabled and generate a fresh logon event.
