<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Strings for the active content scanner.
 *
 * @package    antivirus_activecontent
 * @copyright  2026 DevLMS
 * @license    https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['blockmacros'] = 'Refuse Office files with macros';
$string['blockmacros_desc'] = 'Word, Excel and PowerPoint files that contain macros (VBA), in the new formats (docm, xlsm, pptm, or renamed to docx, xlsx, pptx) and the old ones (doc, xls, ppt).';
$string['blockpdfjs'] = 'Refuse PDFs with JavaScript or launch actions';
$string['blockpdfjs_desc'] = 'PDFs that run JavaScript or ask the reader to open another program, including when hidden in compressed parts of the file. Ordinary fillable forms without scripts are not affected.';
$string['pluginname'] = 'Active content blocker';
$string['privacy:metadata'] = 'The active content blocker stores no personal data. It reads uploaded files and keeps nothing.';
$string['reasonmacros'] = 'it contains macros';
$string['reasonpdfjs'] = 'it contains JavaScript';
$string['reasonpdflaunch'] = 'it asks to open another program';
$string['refused'] = '{$a->item} was not uploaded because {$a->reason}. Save it without macros or scripts (for example as .docx, .xlsx or a printed PDF) and upload it again.';
