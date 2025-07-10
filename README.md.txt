
Cyber Data Analyzer - Full Description

Cyber Data Analyzer is an advanced data analysis tool designed for cybersecurity and digital forensics. It extracts sensitive information from various file types including text files, PDFs, images, spreadsheets, and more.

The tool analyzes data to extract IP addresses, passwords, email addresses, phone numbers, URLs, metadata, timestamps, and classifies user activities based on context — using advanced AI and Natural Language Processing (NLP) techniques.

⸻

Key Features:

Multi-format Support:
Analyze .txt, .json, .html, .pdf, .png, .jpg, .jpeg, .log, .csv, .xlsx files.

Comprehensive Sensitive Data Extraction:
	•	IP addresses (IPv4 & IPv6) with type classification (private, public, device, router).
	•	Password extraction with strength evaluation via the zxcvbn library.
	•	Email extraction with syntactic validation.
	•	Phone number extraction with country identification, type (mobile, landline, virtual), and validity check.
	•	URL extraction and domain analysis.

Contextual Analysis using NLP:
	•	Detect used programs and devices by semantic text analysis.
	•	Classify activity types related to timestamps (login, error, message, file transfer, authentication, etc.).

Timestamp & Timezone Support:
	•	Extract and normalize timestamps from diverse formats with timezone awareness (converted to UTC).
	•	Analyze peak and low activity periods.

Multi-Processor Support:
	•	Automatically utilizes all available CPU cores to speed up processing.

Modern and User-Friendly GUI:
	•	Folder selection for batch analysis.
	•	Display results in a well-organized table with progress bar and percentage.
	•	Save results to a text file.
	•	Copyable text from results window.

⸻

How to Run the Tool:
	1.	Install Required Dependencies:

	•	Install Python (recommended version 3.9+).
	•	Install necessary Python libraries using:

pip install pandas pytesseract pymupdf torch spacy pytz tldextract pillow email-validator phonenumbers zxcvbn dateparser ttkbootstrap

	•	Download the English spaCy model:

python -m spacy download en_core_web_sm

	•	Install Tesseract OCR engine (for image text extraction):
	•	On Windows, download from https://github.com/tesseract-ocr/tesseract
	•	Add Tesseract to your system PATH.

	2.	In the GUI:

	•	Select the folder containing the files you want to analyze.
	•	Click “Start Analysis” to begin.
	•	Watch the progress bar and view results in the table.
	•	Use the “Save to TXT” button to save the analysis output.

⸻

System Requirements:
	•	Operating System: Windows, Linux, or macOS
	•	Python 3.9 or newer
	•	Installed Python libraries listed above
	•	Tesseract OCR installed (for image processing)
	•	Internet connection for initial model/library downloads
	•	At least 2 GB RAM (more recommended for large datasets)
	•	Multi-core CPU to benefit from parallel processing

⸻

Libraries Used in the Program:
	•	pandas
	•	pytesseract
	•	pymupdf (fitz)
	•	torch
	•	multiprocessing (built-in)
	•	mimetypes (built-in)
	•	spacy
	•	pytz
	•	tldextract
	•	pillow (PIL)
	•	email-validator
	•	phonenumbers
	•	zxcvbn
	•	dateparser
	•	ttkbootstrap
	•	tkinter (built-in)
