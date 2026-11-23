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

namespace antivirus_activecontent;

/**
 * Refuses uploads that carry active content: Office macros, PDF JavaScript and PDF launch actions.
 *
 * Files are recognised by their content, not their name, so a macro-enabled workbook renamed to .xlsx is still found.
 * This is not a virus scanner: it blocks the ways documents run code, known or not, and works next to ClamAV.
 *
 * @package    antivirus_activecontent
 * @copyright  2026 DevLMS
 * @license    https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class scanner extends \core\antivirus\scanner {
    /** @var int largest decompressed PDF stream we look into, in bytes */
    private const MAX_STREAM = 20 * 1024 * 1024;

    /** @var string|null why the last file was refused */
    private ?string $reason = null;

    /**
     * Nothing to configure before it works.
     *
     * @return bool
     */
    public function is_configured() {
        return true;
    }

    /**
     * A setting, on unless turned off.
     *
     * @param string $name
     * @return bool
     */
    private function enabled(string $name): bool {
        return !isset($this->config->$name) || !empty($this->config->$name);
    }

    /**
     * Scan one uploaded file.
     *
     * @param string $file path
     * @param string $filename name shown to the user
     * @return int SCAN_RESULT_OK or SCAN_RESULT_FOUND
     */
    public function scan_file($file, $filename) {
        $this->reason = null;
        $head = (string)@file_get_contents($file, false, null, 0, 8);
        if ($this->enabled('blockmacros')) {
            if (str_starts_with($head, "PK\x03\x04")) {
                $this->reason = $this->ooxml_reason($file);
            } else if (str_starts_with($head, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")) {
                $this->reason = $this->ole_reason($file);
            }
        }
        if ($this->reason === null && $this->enabled('blockpdfjs') && $this->is_pdf($file)) {
            $this->reason = $this->pdf_reason((string)file_get_contents($file));
        }
        if ($this->reason === null) {
            return self::SCAN_RESULT_OK;
        }
        $this->set_scanning_notice($this->reason);
        return self::SCAN_RESULT_FOUND;
    }

    /**
     * PDF files may start with junk before %PDF- (readers look in the first kilobyte).
     *
     * @param string $file
     * @return bool
     */
    private function is_pdf(string $file): bool {
        return str_contains((string)@file_get_contents($file, false, null, 0, 1024), '%PDF-');
    }

    /**
     * Office Open XML (docx, xlsx, pptx and their macro versions): a VBA project or a macro-enabled content type.
     *
     * @param string $file
     * @return string|null reason
     */
    private function ooxml_reason(string $file): ?string {
        $zip = new \ZipArchive();
        if ($zip->open($file, \ZipArchive::RDONLY) !== true) {
            return null;
        }
        try {
            for ($i = 0; $i < $zip->numFiles; $i++) {
                if (preg_match('~(^|/)vbaProject\.bin$~i', (string)$zip->getNameIndex($i))) {
                    return get_string('reasonmacros', 'antivirus_activecontent');
                }
            }
            $types = $zip->getFromName('[Content_Types].xml');
            if ($types !== false && stripos($types, 'macroEnabled') !== false) {
                return get_string('reasonmacros', 'antivirus_activecontent');
            }
        } finally {
            $zip->close();
        }
        return null;
    }

    /**
     * Old Office files (doc, xls, ppt) are OLE compound files; macros live in storages named _VBA_PROJECT or Macros.
     *
     * @param string $file
     * @return string|null reason
     */
    private function ole_reason(string $file): ?string {
        $data = (string)file_get_contents($file);
        // Every VBA project has a stream named _VBA_PROJECT; directory names end with a UTF-16 null.
        foreach (['_VBA_PROJECT', '_VBA_PROJECT_CUR'] as $storage) {
            if (str_contains($data, mb_convert_encoding($storage, 'UTF-16LE', 'UTF-8') . "\0\0")) {
                return get_string('reasonmacros', 'antivirus_activecontent');
            }
        }
        return null;
    }

    /**
     * PDF: JavaScript or a launch action, in the objects or inside any stream. Name escapes (#4A) are decoded.
     *
     * Stream bodies are taken out before strings are emptied (a "(" in binary stream data must not swallow the objects
     * after it), then each stream is checked on its own: inflated when compressed, as is when not.
     *
     * @param string $data
     * @param int $depth how many stream layers deep we are
     * @return string|null reason
     */
    private function pdf_reason(string $data, int $depth = 0): ?string {
        preg_match_all('~(<<(?:(?!stream).){0,2000}?>>)\s*stream\r?\n(.*?)\r?\n?endstream~s', $data, $streams, PREG_SET_ORDER);
        $objects = preg_replace('~stream\r?\n.*?endstream~s', 'stream endstream', $data) ?? $data;
        $names = preg_replace_callback(
            '~/[^\s/<>\[\]()]*#[0-9A-Fa-f]{2}[^\s/<>\[\]()]*~',
            fn($m) => preg_replace_callback('~#([0-9A-Fa-f]{2})~', fn($h) => chr(hexdec($h[1])), $m[0]),
            self::without_strings($objects)
        );
        if (preg_match('~/(JavaScript|JS)(?![A-Za-z0-9])~', $names)) {
            return get_string('reasonpdfjs', 'antivirus_activecontent');
        }
        if (preg_match('~/Launch(?![A-Za-z0-9])~', $names)) {
            return get_string('reasonpdflaunch', 'antivirus_activecontent');
        }
        if ($depth > 2) {
            return null;
        }
        foreach ($streams as [, $dictionary, $stream]) {
            $inner = @gzuncompress($stream, self::MAX_STREAM);
            if ($inner === false) {
                $inner = @gzinflate($stream, self::MAX_STREAM);
            }
            if ($inner === false) {
                // Image and other encoded data is binary: only plain (unfiltered) streams are read as they are.
                if (str_contains($dictionary, '/Filter')) {
                    continue;
                }
                $inner = $stream;
            }
            if (($reason = $this->pdf_reason($inner, $depth + 1)) !== null) {
                return $reason;
            }
        }
        return null;
    }

    /**
     * PDF text with its literal strings emptied, so words inside text ("(see /JavaScript)") are not read as names.
     *
     * Strings can nest parentheses and escape them with a backslash; innermost strings are emptied first.
     *
     * @param string $data
     * @return string
     */
    private static function without_strings(string $data): string {
        for ($i = 0; $i < 20; $i++) {
            $next = preg_replace('~\((?:\\.|[^\\()])*\)~s', '<>', $data);
            if ($next === null || $next === $data) {
                break;
            }
            $data = $next;
        }
        return $data;
    }

    /**
     * The message the uploader sees.
     *
     * @return array
     */
    public function get_virus_found_message() {
        return [
            'string' => 'refused',
            'component' => 'antivirus_activecontent',
            'placeholders' => ['reason' => $this->reason ?? ''],
        ];
    }
}
