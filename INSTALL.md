# HIVE — Windows Installation Guide

## What you need

- A Windows machine with internet access (for initial install only)
- Permission to install software (ask IT if unsure)
- Python 3.10 or newer
- Git (optional — you can also download HIVE as a ZIP)

## Step 1 — Install Python

1. Open a browser and go to: https://www.python.org/downloads/
2. Click "Download Python 3.x.x" (the big yellow button)
3. Run the installer
4. IMPORTANT: on the first screen, tick the box that says
   "Add python.exe to PATH" before clicking Install Now
5. Click "Install Now"
6. When it finishes, click "Close"

To verify Python is installed, open Command Prompt and run:
```
python --version
```

You should see something like: Python 3.12.0

## Step 2 — Get HIVE

Option A — Using Git (recommended):
```
git clone https://github.com/YOUR_USERNAME/HIVE.git
cd HIVE
```

Option B — Download ZIP:
1. Go to the HIVE GitHub repository
2. Click the green "Code" button
3. Click "Download ZIP"
4. Extract the ZIP to a folder (e.g. C:\Tools\HIVE)
5. Open Command Prompt and navigate to that folder:
```
cd C:\Tools\HIVE
```

## Step 3 — Create a virtual environment

In the HIVE folder, run:
```
python -m venv .venv
```

This creates an isolated Python environment for HIVE.

## Step 4 — Activate the virtual environment

```
.venv\Scripts\activate
```

You should see (.venv) appear at the start of your prompt.
You need to do this every time you open a new Command Prompt.

## Step 5 — Install HIVE and its dependencies

```
pip install -e .
```

This installs HIVE and all required libraries.
It may take a minute — you will see packages being downloaded.

## Step 6 — Verify the installation

```
hive --version
```

You should see: HIVE 1.2.0

## Running HIVE

Every time you want to use HIVE:
1. Open Command Prompt
2. Navigate to the HIVE folder:
```
cd C:\Tools\HIVE
```
3. Activate the virtual environment:
```
.venv\Scripts\activate
```
4. Run HIVE:
```
hive parse C:\path\to\email.eml -o C:\output
```

## Troubleshooting

"hive is not recognised as a command"
- Make sure you activated the virtual environment (.venv\Scripts\activate)
- If still not working, try: `python -m hive parse <file> -o <output>`

"python is not recognised as a command"
- Python was not added to PATH during installation.
- Reinstall Python and tick "Add python.exe to PATH" on the first screen.

"pip install fails with permission error"
- Run Command Prompt as Administrator, or contact IT.

"No module named hive"
- Make sure you are in the HIVE folder and the virtual environment
  is activated before running `pip install -e .`

For more help see TROUBLESHOOTING.md
