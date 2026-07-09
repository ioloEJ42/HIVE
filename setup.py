from setuptools import find_packages, setup

setup(
    name="hive",
    version="1.0.0",
    description="Header, Indicator & Vector Examiner — email forensics and triage",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "extract-msg==0.55.0",
        "beautifulsoup4==4.13.5",
        "pypdf==6.14.2",
        "python-docx==1.2.0",
        "openpyxl==3.1.5",
        "python-pptx==1.0.2",
        "striprtf==0.0.32",
        "oletools==0.60.2",
    ],
    entry_points={
        "console_scripts": [
            "hive=hive.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Communications :: Email",
    ],
)
