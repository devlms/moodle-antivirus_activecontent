# Active content blocker for Moodle (antivirus_activecontent)

Refuses uploads that can run code on the computer that opens them: Office files with macros, and PDFs with JavaScript or actions that launch another program. A teacher who opens a student's "homework" should not be one click away from a macro.

It is not a virus scanner. A virus scanner (like Moodle's ClamAV plugin) knows known malware; this plugin refuses the ways documents run code at all, known or new. Use both.

## What it refuses

- **Office files with macros (VBA)**: docm, xlsm, pptm, the same files renamed to docx, xlsx or pptx, and old doc, xls and ppt files with a macro project. Files are recognised by their content, not their name.
- **PDFs with JavaScript or launch actions**, including when hidden in compressed parts of the file or written with escaped names. Fillable PDF forms without scripts still upload; forms with calculation scripts (many government forms) are refused while the PDF check is on.

The person uploading sees why, for example: "budget.xlsm was not uploaded because it contains macros. Save it without macros or scripts (for example as .docx, .xlsx or a printed PDF) and upload it again." Administrators get Moodle's usual antivirus notification and, if quarantine is on, the file is kept there.

## Set it up

1. Site administration > Plugins > Antivirus plugins > Manage antivirus plugins: enable **Active content blocker**.
2. Site administration > Plugins > Antivirus plugins > Active content blocker: both checks are on; turn either off if a course needs those files.

## Good to know

- Text that only talks about JavaScript (a programming lecture in PDF) is not refused: the check reads PDF names, not the words on the page, and ignores image data.
- Nothing is stored; the plugin reads each upload and keeps no data.

Moodle 4.5 to 5.3. Built by DevLMS: https://devlms.com
